# BCF Canonical Hash — Specification

**Status:** Draft, Phase 3 step 3.1
**Scope:** Userspace-BCF bundle protocol
**Authority for equivalence:** `__expr_equiv` and `expr_node_equiv` in `bcf-checker/bcf_checker.c` (lines 1149–1281).

---

## 1. Purpose & non-goals

This document specifies a function

```
H : BcfExpr → u64
```

with the **soundness property**

> `expr_equiv(a, b) == 1` ⟹ `H(a) == H(b)`

where `expr_equiv` is the kernel-side BCF equivalence relation defined at
`bcf_checker.c:1268-1274`, invoked under `from_checker = false` semantics
(α-renaming over variable IDs via `var_map` at `bcf_checker.c:1124-1147`).

`H` is the lookup key the kernel uses at refinement sites to retrieve the
proof-derived constraint shipped in a userspace bundle: bundle-side hashes are
computed once at bundle build time; kernel-side hashes are computed at load
time over the kernel's own expression DAG. Equal hash ⇒ candidate match ⇒
followed by an authoritative structural `expr_equiv` check.

**Non-goals.**

- **No semantic equivalence.** `add(1, x)` and `add(x, 1)` are not equal under
  `H` unless they are not equal under `expr_equiv` either — which they aren't,
  because BCF's relation is structural. This matches BCF's strength; no more,
  no less.
- **No commutativity / associativity / identity normalization.**
- **No collision resistance beyond SipHash-2-4's 64-bit budget.** Birthday
  bound is ~2³² distinct expressions before a collision is likely. Bundles
  are emitted by a trusted verifier path; adversarial collision attacks are
  out of scope. The post-hash structural compare at lookup catches collisions.

## 2. Domain

A `BcfExpr` exposes the following fields to the hash:

| Field    | Width | Notes |
|----------|-------|-------|
| `code`   | u8    | Opcode (type in low 3 bits, op in high 5). Determines node kind via `is_var(code)` and `expr_arg_is_id(code)`. |
| `vlen`   | u8    | Number of `args` slots. Implicit in `args.len()` in the Rust representation. |
| `params` | u16   | Opaque per-node parameters; matched bitwise by `expr_node_equiv`. |
| `args`   | u32 × `vlen` | Either child **expr-ids** (non-leaf / var) or raw constant bytes (leaf-const). |

(Widths match the on-disk BCF expression header — see [src/refinement/bcf.rs:153](../../src/refinement/bcf.rs:153) and the kernel `struct bcf_expr` mirrored there.)

**Expr-id convention — slot offsets, not array indices.** An expression with
`vlen = n` consumes `1 + n` `u32` slots on disk (one header slot + `n` arg
slots). The *expr-id* of a node is its **slot offset** from the start of the
expression table, identical to the kernel's `id_to_expr()` lookup key. For a
table `[var, val32, alu(0,1)]` the ids are `0, 1, 3` — *not* `0, 1, 2` —
because `val32` occupies slots `1..3`. Args in non-leaf nodes are these slot
offsets. Implementations must build a slot-offset → array-position lookup
before walking (the kernel does this implicitly via `id_to_expr`; userspace
must do it explicitly).

**Node-kind classification** (mirrors `bcf_checker.c:1110-1113`):

- **Leaf** iff `vlen == 0 || !expr_arg_is_id(code)`.
- **Variable leaf** iff leaf and `is_var(code)`. Per the audit of
  `bcf_checker.c:477,522` and the arity tables (`Nullary = {0,0}` at line
  471), **all `BCF_VAR` nodes have `vlen == 0` and carry no `args`**. A
  variable's *identity* for the renaming relation is the **expr-id of the
  var node itself** (the value by which a parent references it), not any
  field inside the node — see `__expr_equiv` at `bcf_checker.c:1223-1245`,
  where `var_equiv(&map, arg0, arg1, ...)` is called with the parent's arg
  slots, which are expr-ids. BCF additionally uses `make_arg_sharing`
  (`bcf_checker.c:1173-1195`) to collapse duplicate vars to a shared id; the
  renamer below is insensitive to whether sharing has occurred.
- **Constant leaf** iff leaf and not a var.
- **Internal** otherwise.

DAGs are walked **as trees**: arg-sharing produced by `make_arg_sharing`
(`bcf_checker.c:1173-1195`) is not exploited. This matches the recursion in
`__expr_equiv` (`bcf_checker.c:1219-1256`), which descends regardless of
sharing.

## 3. Encoding — byte-stream grammar

`H(e)` is `SipHash-2-4(key = 0¹²⁸, msg = encode(e))`, where `encode` is the
post-order serialization defined below. All multi-byte integers are
little-endian. The byte stream is unambiguous because every record's length
is determined by its tag.

Three tag bytes:

| Tag                | Byte   | Emitted for          |
|--------------------|--------|----------------------|
| `TAG_VAR`          | `0x01` | Variable leaf        |
| `TAG_LEAF_CONST`   | `0x02` | Non-var leaf         |
| `TAG_INTERNAL`     | `0x03` | Internal node        |

### 3.1 Per-node records

**`TAG_VAR` (variable leaf):**

```
0x01 | code:u8 | vlen:u8 | params:u16 | first_occurrence_idx:u32
```

(Total: 9 bytes.) `vlen` is always `0` here (audit of `bcf_checker.c:471,477,522`); it is still
emitted for record-format uniformity and as a defense-in-depth invariant
check. `first_occurrence_idx` is **not** the raw kernel variable id and the
var node carries no `args`. The index is computed by the first-occurrence
renamer (§4), keyed on the **expr-id of the var node itself** — i.e. the
parent's `args` slot that pointed to this var during the post-order walk.

**`TAG_LEAF_CONST` (constant leaf):**

```
0x02 | code:u8 | vlen:u8 | params:u16 | args[0..vlen]:u32 (raw, LE)
```

(Total: 5 + 4·vlen bytes.)

The raw `args` bytes are emitted because `expr_node_equiv` compares them
bitwise on leaves (`bcf_checker.c:1157-1160`).

**`TAG_INTERNAL` (internal node):**

```
0x03 | code:u8 | vlen:u8 | params:u16
```

(Total: 5 bytes.)

Children are not embedded in the parent record. Because the walk is
post-order, every child's record (and its descendants') appears earlier in
the byte stream than its parent's. The grammar is unambiguous because each
record is fixed-width (no variable-length payload appears under
`TAG_INTERNAL`).

### 3.2 Walk order

Post-order, left-to-right over `args[0..vlen]`:

```
encode(e):
    if is_leaf(e):
        if is_var(e):
            emit_var_record(e)
        else:
            emit_leaf_const_record(e)
    else:
        for i in 0..e.vlen:
            encode(e.args[i] resolved via id_to_expr)
        emit_internal_record(e)
```

### 3.3 Worked example

Let `v1`, `v2` be BV vars (`code = BCF_VAR | BCF_BV = 0x18`, `vlen = 0`,
`params = 0`); `add` a `BPF_ADD | BCF_BV = 0x00` internal with `vlen = 2`,
`params = 0`; `mul` a `BPF_MUL | BCF_BV = 0x20` internal with `vlen = 2`,
`params = 0`. (These match the constants in
[src/refinement/bcf.rs](../../src/refinement/bcf.rs).) Let `v1` and `v2`
occupy expr-ids `7` and `9` respectively.

Expression: `add(v1, mul(v2, v1))`.

Post-order visit sequence: `v1`, `v2`, `v1`, `mul`, `add`.

- Visit `v1` (expr-id 7) — first occurrence, index 0:
  `01 18 00 00 00 00 00 00 00`
  (1 tag + 1 code + 1 vlen + 2 params + 4 idx = 9 bytes)
- Visit `v2` (expr-id 9) — first occurrence, index 1:
  `01 18 00 00 00 01 00 00 00`
- Visit `v1` (expr-id 7) again — already mapped to 0:
  `01 18 00 00 00 00 00 00 00`
- Emit `mul`:
  `03 20 02 00 00`
  (1 tag + 1 code + 1 vlen + 2 params = 5 bytes)
- Emit `add`:
  `03 00 02 00 00`

The 64-bit SipHash of this byte string is `H(add(v1, mul(v2, v1)))`.

## 4. First-occurrence renamer

State threaded through one top-level call to `H`:

```
struct FirstOccurrence {
    map: HashMap<ExprId, u32>,  // keyed on the var node's own expr-id
    next: u32,
}
```

On encountering a variable leaf whose expr-id (in the parent's `args` slot)
is `v`:

- If `v ∈ map`: emit `map[v]`.
- Else: assign `idx = next`, insert `(v, idx)`, increment `next`, emit `idx`.

State is **fresh per top-level `H` call**; it does not persist across calls.

This implements the from_checker=false bijection from `var_equiv`
(`bcf_checker.c:1124-1147`) in the forward direction: each distinct kernel
var id maps to exactly one canonical index. The reverse direction (no two
distinct kernel vars share an index) is automatic by construction — we never
re-use a `next` value.

### 4.1 Why this matches `expr_equiv`

Three illustrative cases:

| Pair                           | encoded var-idx seqs    | hash relation     | `expr_equiv`     |
|--------------------------------|-------------------------|-------------------|------------------|
| `f(v1, v2)` vs `f(v3, v4)`     | `[0, 1]` vs `[0, 1]`    | equal             | equiv ✓          |
| `f(v1, v1)` vs `f(v2, v3)`     | `[0, 0]` vs `[0, 1]`    | distinct          | not equiv ✓      |
| `f(v1, v2)` vs `f(v3, v3)`     | `[0, 1]` vs `[0, 0]`    | distinct          | not equiv ✓      |

The bijection is captured by *position-sensitive* indexing during a single
post-order walk; no separate bookkeeping is required.

## 5. Hash primitive

**SipHash-2-4**, 64-bit output, key = 128 zero bits.

Rationale:

- We need a *structural fingerprint*, not a MAC. Bundles are emitted by a
  trusted verifier path under `BPF_PROG_LOAD`; the threat model does not
  include an attacker choosing colliding bundle expressions.
- Both sides of the lookup (bundle-side at build, kernel-side at load) must
  use identical keys. An all-zero key avoids a key-distribution problem.
- SipHash-2-4 is already in the kernel tree (`include/linux/siphash.h`),
  removing a porting risk for the Phase-3 kernel patch.
- 64 bits is sufficient given the expected per-program bundle size
  (≤ ~10⁴ refinement sites; birthday floor at ~2³² is far above this).

## 6. Soundness — informal proof sketch

**Claim.** `expr_equiv(a, b) == 1 ⟹ encode(a) == encode(b)` (and therefore
`H(a) == H(b)`).

**By induction on the call structure of `__expr_equiv`.**

*Base case — leaves.* `expr_node_equiv` (`bcf_checker.c:1149-1163`) requires
matching `code`, `vlen`, `params`, and — on leaves — matching raw `args`
bytes. For constant leaves this fixes the entire `TAG_LEAF_CONST` record. For
variable leaves, `code` and `vlen` match (and `params` matches);
`expr_equiv`'s `from_checker=false` branch (`bcf_checker.c:1240-1245`)
delegates to `var_equiv`, which assigns or confirms a bijective renaming.
The encoder's first-occurrence renamer assigns the same canonical index on
both sides given a position-aligned post-order walk, fixing the
`first_occurrence_idx` field.

*Inductive step — internals.* For an internal node, `expr_node_equiv` fixes
`code`, `vlen`, `params` (the `TAG_INTERNAL` record). The recursive
arg-by-arg walk in `__expr_equiv` (`bcf_checker.c:1223-1256`) visits children
in the same `args` order on both sides; by the induction hypothesis each
child's encoding matches. Concatenation in the same order yields equal
streams.

*Conclusion.* The two encodings are byte-equal, hence `H` agrees.

**Converse not claimed.** Hash collisions are possible. Every lookup hit
**must** be confirmed by a structural `expr_equiv` check on the candidate
kernel-side expression against the bundle-side expression decoded alongside
the hash. This is consistent with how hashmaps are used elsewhere in the
verifier.

## 7. Test vectors (property tests for step 3.1)

The Rust property-test suite must cover at least:

1. **Identity.** `H(e) == H(e)` for arbitrary `e`.
2. **Determinism across calls.** Two independent calls with fresh state
   produce equal output on equal input.
3. **α-renaming.** `f(v_a, v_b)` and `f(v_c, v_d)` with `a≠b`, `c≠d` hash
   equal regardless of choice of distinct ids.
4. **Bijectivity discriminates.** `f(v1, v1)` ≠ `f(v2, v3)` and `f(v1, v2)` ≠
   `f(v3, v3)` (both directions of the var_map invariant).
5. **`code` discriminates.** Two expressions identical except for `code`
   hash differently.
6. **`params` discriminates.** Two expressions identical except for
   `params` hash differently (covers BCF-specific param bits that are
   semantically meaningful, e.g. width selectors).
7. **`args` discriminates on leaves.** Two `TAG_LEAF_CONST` nodes differing
   only in raw `args` bytes hash differently.
8. **DAG sharing irrelevance.** An expression built as a DAG (one shared
   subterm referenced twice) hashes equal to the same expression built as a
   tree (subterm duplicated structurally).
9. **Order matters.** `f(a, b)` ≠ `f(b, a)` for non-trivially distinct `a`,
   `b` (BCF is structural).
10. **Cross-side property — deferred to step 3.4.** Construct an `(a, b)`
    pair and assert: if BCF's actual `__expr_equiv(a, b, from_checker=false,
    own_args=false)` returns 1, then `H(a) == H(b)`. *Not implemented in
    step 3.1.* `bcf-checker`'s public CLI does not expose `__expr_equiv`
    directly with `from_checker=false`; driving it requires either building
    a complete refutation proof (heavy) or patching the upstream BCF source
    tree to add a thin harness. Step 3.4 (kernel patch) will integrate both
    sides against real verifier expressions and naturally subsume this
    synthetic-oracle check. Tests 1–9 above + the byte-stream conformance
    test (§3.3) + §6's soundness sketch are the standing correctness
    argument for step 3.1.

## 8. Implementation contract

To be delivered in step 3.1 immediately after sign-off on this spec.

- **Crate:** `bcf-canonical-hash` (new), within the existing workspace.
- **Public API:**
  ```rust
  pub fn hash_expr(root: u32, exprs: &[BcfExpr]) -> u64;
  ```
  `root` is the expression id; `exprs` is the bundle-side expression table
  indexed by id. The kernel-side hasher (step 3.4) will be written in C and
  shares only the *spec*, not the Rust code, so no trait abstraction is
  warranted at this stage.
- **Determinism:** No reliance on `HashMap` iteration order, allocator
  addresses, or thread-local state. The first-occurrence map is keyed by
  `VarId` (u32) and only read via insert-or-get; iteration order is never
  observed.
- **Allocation:** Single growable `Vec<u8>` for the encoded stream; reset
  per top-level call. (We may later switch to a streaming SipHash feed; the
  spec is agnostic.)
- **Test surface:** Property tests in §7, plus the cross-side corpus check
  gated behind a feature flag that links against the BCF checker.

## 8.1 C reference implementation

Lives at [c-ref/canonical_hash.{h,c}](../../c-ref/), with a
vendored header-only SipHash-2-4 at `c-ref/siphash24.h`. The C impl
shares no headers with the Rust impl; agreement is enforced by the
`cross_impl_agrees` test in [src/refinement/canonical_hash.rs](../../src/refinement/canonical_hash.rs),
which drives a stdin-fed CLI harness (`canonical_hash_tool`) over 15
fixtures and asserts byte-for-byte hash equality. The eventual kernel patch
(step 3.4) can either pull `siphash24.h` in directly or substitute
`include/linux/siphash.h` — both produce identical output by spec.

## 9. Open questions / deferred

- **Memoization for performance.** A single-pass walk is O(tree-size), which
  is exponential in pathological DAG-sharing cases. We accept this for the
  spec — it matches BCF's own behavior — and revisit if profiling on the
  Cilium corpus shows it matters.
- **Hash width.** 64 bits is a deliberate Phase-3 choice. If observed
  collision rates on real bundles exceed budget, escalate to 128-bit
  SipHash output or Blake3-128. Bundle UAPI (step 3.2) should leave room
  for a wider field if necessary.
- **Opcodes not yet seen.** Phase-2 corpus exercises a subset of `code`
  values. Any new opcode introduced in later phases falls into one of the
  three tag classes by virtue of `is_var` / `is_leaf_node` and requires no
  spec change.
- ~~**Var-record `args[1..]` bytes.**~~ Resolved by audit prior to coding:
  all `BCF_VAR` opcodes are `Nullary` (`bcf_checker.c:471,477,522`), so var
  nodes have `vlen == 0` and no `args`. The `TAG_VAR` record needs no
  trailing arg payload.
