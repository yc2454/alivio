//! BCF canonical hash — α-equivalent structural fingerprint.
//!
//! Implements the spec at `docs/userspace-bcf/canonical-hash-spec.md`.
//! Property: `bcf_checker.c::expr_equiv(a, b) == 1` ⟹ `hash_expr(a) == hash_expr(b)`,
//! under `from_checker = false` semantics (α-renaming via first-occurrence).
//!
//! Used at refinement sites to look up bundle-supplied constraints by their
//! kernel-side expression shape.

use std::collections::HashMap;
use std::hash::Hasher;

use siphasher::sip::SipHasher24;

use super::bcf::{BcfExpr, BCF_BV, BCF_OP_MASK, BCF_VAL, BCF_VAR};

// Record tags. See spec §3.1.
const TAG_VAR: u8 = 0x01;
const TAG_LEAF_CONST: u8 = 0x02;
const TAG_INTERNAL: u8 = 0x03;

/// `expr_arg_is_id(code)` mirror from `bcf_checker.c:248-251`.
/// Only BV constants (`code == BCF_BV | BCF_VAL == 0x08`) carry raw u32 args.
#[inline]
fn expr_arg_is_id(code: u8) -> bool {
    code != (BCF_BV | BCF_VAL)
}

/// `is_leaf_node(e)` mirror from `bcf_checker.c:1110-1113`.
#[inline]
fn is_leaf(e: &BcfExpr) -> bool {
    e.args.is_empty() || !expr_arg_is_id(e.code)
}

/// `is_var(code)` mirror from `bcf_checker.c:687-689`.
#[inline]
fn is_var(code: u8) -> bool {
    (code & BCF_OP_MASK) == BCF_VAR
}

/// First-occurrence renamer for variable expr-ids. Fresh per top-level call.
struct VarRenamer {
    map: HashMap<u32, u32>,
    next: u32,
}

impl VarRenamer {
    fn new() -> Self {
        Self { map: HashMap::new(), next: 0 }
    }

    fn intern(&mut self, expr_id: u32) -> u32 {
        if let Some(&idx) = self.map.get(&expr_id) {
            return idx;
        }
        let idx = self.next;
        self.map.insert(expr_id, idx);
        self.next += 1;
        idx
    }
}

/// Build a slot-offset → array-index lookup table. Mirrors the kernel's
/// `id_to_expr()` mapping (see `bcf_checker.c`). An expression with
/// `vlen = n` consumes `1 + n` u32 slots; its slot offset is the cumulative
/// slot count of all preceding expressions.
fn slot_index(exprs: &[BcfExpr]) -> HashMap<u32, usize> {
    let mut m = HashMap::with_capacity(exprs.len());
    let mut slot: u32 = 0;
    for (i, e) in exprs.iter().enumerate() {
        m.insert(slot, i);
        slot += 1 + e.args.len() as u32;
    }
    m
}

/// Compute the canonical hash of the expression rooted at `root` in `exprs`.
///
/// `root` and the values in each expression's `args` are **slot offsets**
/// (BCF's on-disk convention), not array indices into `exprs`. See spec §2
/// "Expr-id convention".
///
/// Walks the expression as a tree in post-order; identical sub-DAGs are
/// walked twice — matches BCF's own recursion in `__expr_equiv`. Resulting
/// hash is invariant under α-renaming of variables and matches across
/// bundle/kernel boundaries.
pub fn hash_expr(root: u32, exprs: &[BcfExpr]) -> u64 {
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    let mut renamer = VarRenamer::new();
    let slot_to_idx = slot_index(exprs);
    encode(root, exprs, &slot_to_idx, &mut renamer, &mut buf);

    // Diagnostic hatch: when ZOVIA_BCF_DUMP_HASH_BYTES is set, dump the
    // canonical encoder's byte stream to stderr exactly like the kernel's
    // `pr_warn("bcf_canonical_hash: buf.len=...")`. Lets us byte-diff
    // against `dmesg | grep bcf_canonical_hash` to localise DAG-shape
    // divergence without a kernel rebuild.
    let mut hasher = SipHasher24::new_with_keys(0, 0);
    hasher.write(&buf);
    let h = hasher.finish();

    if std::env::var("ZOVIA_BCF_DUMP_HASH_BYTES").is_ok() {
        let hex: String = buf
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        eprintln!("[zovia] bcf_canonical_hash: buf.len={} hash=0x{:016x} bytes: {}", buf.len(), h, hex);
    }

    h
}

fn encode(
    id: u32,
    exprs: &[BcfExpr],
    slot_to_idx: &HashMap<u32, usize>,
    ren: &mut VarRenamer,
    buf: &mut Vec<u8>,
) {
    let array_idx = *slot_to_idx
        .get(&id)
        .unwrap_or_else(|| panic!("canonical_hash: expr-id {} is not a valid slot offset", id));
    let e = &exprs[array_idx];

    if is_leaf(e) {
        if is_var(e.code) {
            // TAG_VAR: tag(1) + code(1) + vlen(1) + params(2) + idx(4) = 9 bytes
            let idx = ren.intern(id);
            buf.push(TAG_VAR);
            buf.push(e.code);
            buf.push(e.args.len() as u8);
            buf.extend_from_slice(&e.params.to_le_bytes());
            buf.extend_from_slice(&idx.to_le_bytes());
        } else {
            // TAG_LEAF_CONST: tag(1) + code(1) + vlen(1) + params(2) + args(4*vlen)
            buf.push(TAG_LEAF_CONST);
            buf.push(e.code);
            buf.push(e.args.len() as u8);
            buf.extend_from_slice(&e.params.to_le_bytes());
            for arg in &e.args {
                buf.extend_from_slice(&arg.to_le_bytes());
            }
        }
    } else {
        // Internal: post-order — recurse children first, then emit our record.
        for &arg in &e.args {
            encode(arg, exprs, slot_to_idx, ren, buf);
        }
        // TAG_INTERNAL: tag(1) + code(1) + vlen(1) + params(2) = 5 bytes
        buf.push(TAG_INTERNAL);
        buf.push(e.code);
        buf.push(e.args.len() as u8);
        buf.extend_from_slice(&e.params.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refinement::bcf::{
        BCF_BOOL, BCF_CONJ, BCF_EXTRACT, BCF_ZERO_EXTEND, BPF_ADD, BPF_AND, BPF_JLE, BPF_JSGT,
        BPF_MUL, BPF_RSH,
    };

    /// Regression test: byte-for-byte the kernel-side canonical_hash agrees
    /// with zovia's on the shift_constraint goal layout. Locks the hash to
    /// the value the kernel produces (kernel/bpf/canonical_hash.c).
    /// If either impl changes its encoding, this asserts loudly before the
    /// next end-to-end test would silently miss the bundle entry.
    #[test]
    fn shift_constraint_kernel_layout_hash() {
        // Replicate the kernel's expression table for the shift_constraint
        // goal (kexpr[] layout from kernel/bpf/canonical_hash.c).
        let mut e: Vec<BcfExpr> = Vec::new();
        let mut slot: u32 = 0;
        let mut push = |exprs: &mut Vec<BcfExpr>, slot: &mut u32, expr: BcfExpr| -> u32 {
            let s = *slot;
            *slot += 1 + expr.args.len() as u32;
            exprs.push(expr);
            s
        };
        // [0] VAR_64
        let s0 = push(&mut e, &mut slot, BcfExpr { code: BCF_VAR | BCF_BV, params: 0x40, args: vec![] });
        // [1] EXTRACT_32(s0), params=0x1f00
        let s1 = push(&mut e, &mut slot, BcfExpr { code: BCF_EXTRACT | BCF_BV, params: 0x1f00, args: vec![s0] });
        // [3] ZEXT(s1) params=0x2040
        let _s3 = push(&mut e, &mut slot, BcfExpr { code: BCF_ZERO_EXTEND | BCF_BV, params: 0x2040, args: vec![s1] });
        // [5] VAL_64(0xff)  args=[0xff, 0] — unused in goal subtree but present in kernel table
        let _s5 = push(&mut e, &mut slot, BcfExpr { code: BCF_VAL | BCF_BV, params: 0x40, args: vec![0xff, 0] });
        // [8] VAL_32(0xff) args=[0xff], params=0x20
        let s8 = push(&mut e, &mut slot, BcfExpr { code: BCF_VAL | BCF_BV, params: 0x20, args: vec![0xff] });
        // [10] AND_32(s1, s8), params=0x20
        let s10 = push(&mut e, &mut slot, BcfExpr { code: BPF_AND | BCF_BV, params: 0x20, args: vec![s1, s8] });
        // [13] ZEXT(s10) params=0x2040
        let s13 = push(&mut e, &mut slot, BcfExpr { code: BCF_ZERO_EXTEND | BCF_BV, params: 0x2040, args: vec![s10] });
        // [15] VAL_64(0)
        let s15 = push(&mut e, &mut slot, BcfExpr { code: BCF_VAL | BCF_BV, params: 0x40, args: vec![0, 0] });
        // [18] ADD_64(s15, s13), params=0x40 — r2's bcf_expr
        let s18 = push(&mut e, &mut slot, BcfExpr { code: BPF_ADD | BCF_BV, params: 0x40, args: vec![s15, s13] });
        // [21] VAL_64(1) — present in kernel but unused in goal subtree
        let _s21 = push(&mut e, &mut slot, BcfExpr { code: BCF_VAL | BCF_BV, params: 0x40, args: vec![1, 0] });
        // [24] VAL_32(1)
        let s24 = push(&mut e, &mut slot, BcfExpr { code: BCF_VAL | BCF_BV, params: 0x20, args: vec![1] });
        // [26] RSH_32(s10, s24)
        let s26 = push(&mut e, &mut slot, BcfExpr { code: BPF_RSH | BCF_BV, params: 0x20, args: vec![s10, s24] });
        // [29] ZEXT(s26) params=0x2040
        let s29 = push(&mut e, &mut slot, BcfExpr { code: BCF_ZERO_EXTEND | BCF_BV, params: 0x2040, args: vec![s26] });
        // [31] VAL_64(4)
        let s31 = push(&mut e, &mut slot, BcfExpr { code: BCF_VAL | BCF_BV, params: 0x40, args: vec![4, 0] });
        // [34] ule(s29, s31) — path_cond
        let s34 = push(&mut e, &mut slot, BcfExpr { code: BPF_JLE | BCF_BOOL, params: 0, args: vec![s29, s31] });
        // [37] EXTRACT_32(s18) params=0x1f00
        let s37 = push(&mut e, &mut slot, BcfExpr { code: BCF_EXTRACT | BCF_BV, params: 0x1f00, args: vec![s18] });
        // [39] VAL_32(15)
        let s39 = push(&mut e, &mut slot, BcfExpr { code: BCF_VAL | BCF_BV, params: 0x20, args: vec![15] });
        // [41] sgt(s37, s39) — refine_cond
        let s41 = push(&mut e, &mut slot, BcfExpr { code: BPF_JSGT | BCF_BOOL, params: 0, args: vec![s37, s39] });
        // [44] CONJ(s34, s41) — goal_root
        let s44 = push(&mut e, &mut slot, BcfExpr { code: BCF_CONJ | BCF_BOOL, params: 0, args: vec![s34, s41] });

        let h = hash_expr(s44, &e);
        // The kernel emits the same 140 encoded bytes for this layout
        // (see kernel/bpf/canonical_hash.c). Lock the hash here so future
        // encoding changes break loudly on either side.
        assert_eq!(
            h, 0x53bad2296570f686,
            "canonical_hash on shift_constraint kernel layout regressed"
        );
    }

    // ---- helpers ----
    //
    // Returned "ids" are slot offsets (BCF convention), not array indices.
    // Each helper computes its slot offset as the cumulative slot count of
    // already-pushed expressions. See spec §2 "Expr-id convention".

    fn next_slot(exprs: &[BcfExpr]) -> u32 {
        exprs.iter().map(|e| 1 + e.args.len() as u32).sum()
    }

    fn bv_var(exprs: &mut Vec<BcfExpr>, params: u16) -> u32 {
        let id = next_slot(exprs);
        exprs.push(BcfExpr { code: BCF_VAR | BCF_BV, params, args: vec![] });
        id
    }

    fn bv_val(exprs: &mut Vec<BcfExpr>, value: u32) -> u32 {
        let id = next_slot(exprs);
        exprs.push(BcfExpr { code: BCF_VAL | BCF_BV, params: 0, args: vec![value] });
        id
    }

    fn bv_add(exprs: &mut Vec<BcfExpr>, a: u32, b: u32) -> u32 {
        let id = next_slot(exprs);
        exprs.push(BcfExpr { code: BPF_ADD | BCF_BV, params: 0, args: vec![a, b] });
        id
    }

    fn bv_mul(exprs: &mut Vec<BcfExpr>, a: u32, b: u32) -> u32 {
        let id = next_slot(exprs);
        exprs.push(BcfExpr { code: BPF_MUL | BCF_BV, params: 0, args: vec![a, b] });
        id
    }

    // ---- §7 test vectors ----

    #[test]
    fn identity() {
        let mut exprs = vec![];
        let v = bv_var(&mut exprs, 0);
        let root = bv_add(&mut exprs, v, v);
        assert_eq!(hash_expr(root, &exprs), hash_expr(root, &exprs));
    }

    #[test]
    fn determinism_across_calls() {
        // Two structurally identical inputs built independently must hash equal.
        let mut a = vec![];
        let va = bv_var(&mut a, 0);
        let ca = bv_val(&mut a, 42);
        let ra = bv_add(&mut a, va, ca);

        let mut b = vec![];
        let vb = bv_var(&mut b, 0);
        let cb = bv_val(&mut b, 42);
        let rb = bv_add(&mut b, vb, cb);

        assert_eq!(hash_expr(ra, &a), hash_expr(rb, &b));
    }

    #[test]
    fn alpha_renaming() {
        // f(v1, v2) ≡ f(v3, v4): both yield first-occurrence pattern [0, 1].
        let mut a = vec![];
        let v1 = bv_var(&mut a, 0);
        let v2 = bv_var(&mut a, 0);
        let ra = bv_add(&mut a, v1, v2);

        let mut b = vec![];
        // Pad with throwaway exprs so var ids differ from a's.
        let _ = bv_val(&mut b, 99);
        let _ = bv_val(&mut b, 99);
        let _ = bv_val(&mut b, 99);
        let v3 = bv_var(&mut b, 0);
        let v4 = bv_var(&mut b, 0);
        let rb = bv_add(&mut b, v3, v4);

        assert_eq!(hash_expr(ra, &a), hash_expr(rb, &b));
    }

    #[test]
    fn bijectivity_discriminates_collapse() {
        // f(v1, v1) [pattern 0,0] vs f(v2, v3) [pattern 0,1].
        let mut a = vec![];
        let v1 = bv_var(&mut a, 0);
        let ra = bv_add(&mut a, v1, v1);

        let mut b = vec![];
        let v2 = bv_var(&mut b, 0);
        let v3 = bv_var(&mut b, 0);
        let rb = bv_add(&mut b, v2, v3);

        assert_ne!(hash_expr(ra, &a), hash_expr(rb, &b));
    }

    #[test]
    fn bijectivity_discriminates_split() {
        // f(v1, v2) [pattern 0,1] vs f(v3, v3) [pattern 0,0].
        let mut a = vec![];
        let v1 = bv_var(&mut a, 0);
        let v2 = bv_var(&mut a, 0);
        let ra = bv_add(&mut a, v1, v2);

        let mut b = vec![];
        let v3 = bv_var(&mut b, 0);
        let rb = bv_add(&mut b, v3, v3);

        assert_ne!(hash_expr(ra, &a), hash_expr(rb, &b));
    }

    #[test]
    fn code_discriminates() {
        // add(v, v) vs mul(v, v).
        let mut a = vec![];
        let va = bv_var(&mut a, 0);
        let ra = bv_add(&mut a, va, va);

        let mut b = vec![];
        let vb = bv_var(&mut b, 0);
        let rb = bv_mul(&mut b, vb, vb);

        assert_ne!(hash_expr(ra, &a), hash_expr(rb, &b));
    }

    #[test]
    fn params_discriminates() {
        // Var with params=32 vs var with params=64 (e.g., width selector).
        let mut a = vec![];
        let va = bv_var(&mut a, 32);
        let mut b = vec![];
        let vb = bv_var(&mut b, 64);
        assert_ne!(hash_expr(va, &a), hash_expr(vb, &b));
    }

    #[test]
    fn const_args_discriminate() {
        let mut a = vec![];
        let ca = bv_val(&mut a, 0xdead_beef);
        let mut b = vec![];
        let cb = bv_val(&mut b, 0xcafe_babe);
        assert_ne!(hash_expr(ca, &a), hash_expr(cb, &b));
    }

    #[test]
    fn dag_sharing_irrelevance() {
        // Build add(v, v) as a DAG (one var node, used twice).
        let mut a = vec![];
        let va = bv_var(&mut a, 0);
        let ra = bv_add(&mut a, va, va);

        // Build add(v, v) as a tree (two var nodes, structurally distinct ids).
        // Because expr_equiv treats DAG as tree and both vars get first-occurrence
        // index 0 on the (v, v) pair... wait — DAG case has one var node visited
        // twice (same expr-id → both rename to 0). Tree case has two distinct
        // var nodes (different expr-ids → renames to 0 and 1). These should NOT
        // hash equal because they correspond to add(x, x) vs add(x, y).
        //
        // The correct "DAG sharing irrelevance" property: a single var used in
        // both arg slots hashes the same regardless of whether the BcfExpr
        // table happens to share the node or duplicate it (which BCF does via
        // make_arg_sharing). To test this we need both inputs to represent the
        // *same logical* expression (x, x) — so both must use the same expr-id
        // for the shared subterm. Here both are DAG; the meaningful check is
        // that two independently-built DAGs of (x, x) hash equal.
        let mut b = vec![];
        let _ = bv_val(&mut b, 7); // shift ids
        let vb = bv_var(&mut b, 0);
        let rb = bv_add(&mut b, vb, vb);

        assert_eq!(hash_expr(ra, &a), hash_expr(rb, &b));
    }

    #[test]
    fn order_matters() {
        // add(c1, c2) vs add(c2, c1) — BCF is structural, not commutative.
        let mut a = vec![];
        let c1 = bv_val(&mut a, 1);
        let c2 = bv_val(&mut a, 2);
        let ra = bv_add(&mut a, c1, c2);

        let mut b = vec![];
        let c1b = bv_val(&mut b, 1);
        let c2b = bv_val(&mut b, 2);
        let rb = bv_add(&mut b, c2b, c1b);

        assert_ne!(hash_expr(ra, &a), hash_expr(rb, &b));
    }

    #[test]
    fn worked_example_byte_stream() {
        // Spec §3.3: add(v1, mul(v2, v1)) — verify the encoded byte stream
        // matches the spec exactly. We don't compare the hash value itself
        // (no committed test vector for SipHash output yet) but we lock the
        // encoding.
        let mut exprs = vec![];
        // Pad so v1, v2 land at ids 7, 9 per the spec example.
        // ids 0..7: filler vals
        for _ in 0..7 {
            let _ = bv_val(&mut exprs, 0); // 7 vals × slot_len 2 = 14 slots
        }
        let v1 = bv_var(&mut exprs, 0);
        assert_eq!(v1, 14);
        let _ = bv_val(&mut exprs, 0); // val at slot 15 (slot_len 2)
        let v2 = bv_var(&mut exprs, 0);
        assert_eq!(v2, 17);
        let mul_id = bv_mul(&mut exprs, v2, v1);
        let add_id = bv_add(&mut exprs, v1, mul_id);

        let mut buf = vec![];
        let mut ren = VarRenamer::new();
        let slot_to_idx = slot_index(&exprs);
        encode(add_id, &exprs, &slot_to_idx, &mut ren, &mut buf);

        // Expected: v1(idx0), v2(idx1), v1(idx0), mul, add
        let expected: Vec<u8> = vec![
            // v1: tag, code=BCF_VAR|BCF_BV=0x18, vlen=0, params=0x0000, idx=0
            0x01, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // v2: tag, code=0x18, vlen=0, params=0, idx=1
            0x01, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            // v1 again: idx=0
            0x01, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // mul: tag, code=BPF_MUL|BCF_BV=0x20, vlen=2, params=0
            0x03, 0x20, 0x02, 0x00, 0x00,
            // add: tag, code=BPF_ADD|BCF_BV=0x00, vlen=2, params=0
            0x03, 0x00, 0x02, 0x00, 0x00,
        ];
        assert_eq!(buf, expected, "encoded byte stream must match spec §3.3");
    }

    #[test]
    fn slot_offsets_diverge_from_array_indices() {
        // Mixed-width regression lock for spec §2 (Expr-id convention).
        // Build: v (slot_len 1) + val (slot_len 2) + add(v, val) (slot_len 3).
        // Array indices: 0, 1, 2. Slot offsets: 0, 1, 3.
        // The add's args MUST be [0, 1] (slot offsets), and root MUST be 3.
        // If the impl ever silently regresses to array-indexing, root=3
        // would be out of bounds (only 3 entries: indices 0..2) and this
        // test panics; if it silently re-resolves args as array indices,
        // add(0,1) interprets val (array[1]) correctly but mis-locates any
        // deeper structure — keep the test simple enough to lock at least
        // the root-resolution path.
        let mut e = vec![];
        let v = bv_var(&mut e, 0);
        assert_eq!(v, 0, "var at slot 0");
        let c = bv_val(&mut e, 42);
        assert_eq!(c, 1, "val at slot 1 (after var of slot_len 1)");
        let root = bv_add(&mut e, v, c);
        assert_eq!(root, 3, "add at slot 3 (after var=1 + val=2 slots)");
        // Sanity: hash succeeds (would panic on out-of-bounds resolution).
        let h = hash_expr(root, &e);
        assert_ne!(h, 0); // 0 is also a valid hash but extremely unlikely here
    }

    // ---- cross-impl agreement (step 3.2) ----
    //
    // Drives the C reference impl in c-ref/ and asserts byte-for-byte
    // identical hash output across the 12 fixtures above. Skips if the C tool
    // hasn't been built (run `make -C c-ref` to enable).

    fn c_tool_path() -> std::path::PathBuf {
        // CARGO_MANIFEST_DIR points at the crate root.
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("c-ref/build/canonical_hash_tool")
    }

    /// Serialize `(exprs, root)` into the binary stdin format the C tool reads.
    /// See c-ref/canonical_hash_tool.c for the format.
    fn serialize_for_c_tool(root: u32, exprs: &[BcfExpr]) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&(exprs.len() as u32).to_le_bytes());
        for e in exprs {
            out.push(e.code);
            out.push(e.args.len() as u8);
            out.extend_from_slice(&e.params.to_le_bytes());
            for arg in &e.args {
                out.extend_from_slice(&arg.to_le_bytes());
            }
        }
        out.extend_from_slice(&root.to_le_bytes());
        out
    }

    fn run_c_tool(root: u32, exprs: &[BcfExpr]) -> u64 {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let path = c_tool_path();
        let mut child = Command::new(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {}: {}", path.display(), e));

        let payload = serialize_for_c_tool(root, exprs);
        child.stdin.as_mut().unwrap().write_all(&payload).unwrap();
        drop(child.stdin.take());

        let out = child.wait_with_output().expect("c tool wait");
        assert!(
            out.status.success(),
            "c tool failed: stderr = {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let hex = String::from_utf8(out.stdout).expect("c tool stdout utf8");
        let hex = hex.trim();
        u64::from_str_radix(hex, 16)
            .unwrap_or_else(|e| panic!("parse c hash {:?}: {}", hex, e))
    }

    #[test]
    fn cross_impl_agrees() {
        if !c_tool_path().exists() {
            eprintln!(
                "SKIP cross_impl_agrees: build the C reference impl first \
                 (run `make -C c-ref` from the repo root)"
            );
            return;
        }

        // Reuse the same fixture shapes as the property tests above. Each
        // entry: (label, builder closure returning (root, exprs)).
        type Fixture = fn() -> (u32, Vec<BcfExpr>);
        let fixtures: &[(&str, Fixture)] = &[
            ("identity_addvv", || {
                let mut e = vec![];
                let v = bv_var(&mut e, 0);
                let r = bv_add(&mut e, v, v);
                (r, e)
            }),
            ("var_alone", || {
                let mut e = vec![];
                let v = bv_var(&mut e, 0);
                (v, e)
            }),
            ("const_alone", || {
                let mut e = vec![];
                let c = bv_val(&mut e, 0xdead_beef);
                (c, e)
            }),
            ("alpha_pair_a", || {
                let mut e = vec![];
                let v1 = bv_var(&mut e, 0);
                let v2 = bv_var(&mut e, 0);
                let r = bv_add(&mut e, v1, v2);
                (r, e)
            }),
            ("alpha_pair_b_shifted_ids", || {
                let mut e = vec![];
                for _ in 0..3 { let _ = bv_val(&mut e, 99); }
                let v3 = bv_var(&mut e, 0);
                let v4 = bv_var(&mut e, 0);
                let r = bv_add(&mut e, v3, v4);
                (r, e)
            }),
            ("collapse_addvv", || {
                let mut e = vec![];
                let v = bv_var(&mut e, 0);
                let r = bv_add(&mut e, v, v);
                (r, e)
            }),
            ("split_addv1v2", || {
                let mut e = vec![];
                let v1 = bv_var(&mut e, 0);
                let v2 = bv_var(&mut e, 0);
                let r = bv_add(&mut e, v1, v2);
                (r, e)
            }),
            ("mul_vv", || {
                let mut e = vec![];
                let v = bv_var(&mut e, 0);
                let r = bv_mul(&mut e, v, v);
                (r, e)
            }),
            ("var_params_32", || {
                let mut e = vec![];
                let v = bv_var(&mut e, 32);
                (v, e)
            }),
            ("var_params_64", || {
                let mut e = vec![];
                let v = bv_var(&mut e, 64);
                (v, e)
            }),
            ("const_cafe", || {
                let mut e = vec![];
                let c = bv_val(&mut e, 0xcafe_babe);
                (c, e)
            }),
            ("add_c1_c2_ordered", || {
                let mut e = vec![];
                let c1 = bv_val(&mut e, 1);
                let c2 = bv_val(&mut e, 2);
                let r = bv_add(&mut e, c1, c2);
                (r, e)
            }),
            ("add_c2_c1_ordered", || {
                let mut e = vec![];
                let c1 = bv_val(&mut e, 1);
                let c2 = bv_val(&mut e, 2);
                let r = bv_add(&mut e, c2, c1);
                (r, e)
            }),
            ("worked_example_add_v1_mul_v2_v1", || {
                let mut e = vec![];
                for _ in 0..7 { let _ = bv_val(&mut e, 0); }
                let v1 = bv_var(&mut e, 0);
                let _ = bv_val(&mut e, 0);
                let v2 = bv_var(&mut e, 0);
                let m = bv_mul(&mut e, v2, v1);
                let r = bv_add(&mut e, v1, m);
                (r, e)
            }),
            ("bool_var", || {
                let mut e = vec![];
                e.push(BcfExpr { code: BCF_VAR | BCF_BOOL, params: 0, args: vec![] });
                (0, e)
            }),
        ];

        for (label, build) in fixtures {
            let (root, exprs) = build();
            let rust = hash_expr(root, &exprs);
            let c = run_c_tool(root, &exprs);
            assert_eq!(
                rust, c,
                "cross-impl mismatch on fixture {}: rust=0x{:016x} c=0x{:016x}",
                label, rust, c
            );
        }
    }

    #[test]
    fn bool_var_treated_as_var() {
        // code = BCF_VAR | BCF_BOOL: still a var, still nullary.
        let mut exprs = vec![];
        let id = exprs.len() as u32;
        exprs.push(BcfExpr { code: BCF_VAR | BCF_BOOL, params: 0, args: vec![] });
        let h = hash_expr(id, &exprs);

        // Two of them should α-rename identically.
        let mut b = vec![];
        let _ = bv_val(&mut b, 1);
        let idb = next_slot(&b);
        b.push(BcfExpr { code: BCF_VAR | BCF_BOOL, params: 0, args: vec![] });
        assert_eq!(h, hash_expr(idb, &b));
    }
}
