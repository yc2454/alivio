//! Symbolic state for BCF-style refinement.
//!
//! Mirrors the kernel's `struct bcf_state` plus per-register `bcf_expr`
//! tracking (kernel patches set1/0005–0011). During refinement, this state
//! captures the precise program state along the analysis suffix as a DAG of
//! [`BcfExpr`]s plus accumulated path conditions.
//!
//! This module provides the **primitive** state-manipulation API. Higher-level
//! transfer functions (the `bcf_alu` / `bcf_mov32` / `bcf_sx` analogues) and
//! site-specific refinement-condition formulators (`bcf_refine_access_bound`
//! analogues) live in sibling modules and call into these primitives.
//!
//! The "index" of an expression is its **u32 slot offset** from the start of
//! the expression table — identical to the on-disk BCF binary format. An
//! expression with `vlen = n` consumes `1 + n` slots (header + n args).

use super::bcf::*;

/// Number of BPF registers (R0–R10).
pub const NUM_REGS: usize = 11;

/// Snapshot of a register's abstract-domain bounds in a form usable by
/// [`SymbolicState::reg_expr`]. Mirrors the subset of kernel
/// `struct bpf_reg_state` fields that BCF's `bcf_reg_expr` consults
/// (verifier.c:882-914).
///
/// Field semantics match the kernel:
/// - `const_val`: `Some(v)` if the abstract value is the singleton {v}.
/// - `smin` / `smax`: signed 64-bit interval.
/// - `s32_min` / `s32_max`: signed 32-bit interval (when the value
///   represents a 32-bit subreg, these are the same as smin/smax cast).
/// - `u32_min` / `u32_max`: unsigned 32-bit interval.
///
/// 64-bit unsigned bounds are not stored explicitly; [`bound_reg64`]
/// derives them from `smin`/`smax` when the sign is determinate.
#[derive(Debug, Clone, Copy)]
pub struct RegBounds {
    pub const_val: Option<u64>,
    pub smin: i64,
    pub smax: i64,
    /// 64-bit unsigned interval (kernel `umin_value` / `umax_value`),
    /// tracked INDEPENDENTLY of the signed interval. `bound_reg64` emits
    /// `ULE(reg, umax)` from this directly rather than deriving it from
    /// `smax`, so a reg with `umax=0xffffffff` but `smax=0x7fffffff`
    /// (e.g. a zero-extended jump-table index) yields BOTH bound preds,
    /// matching the kernel's `bcf_bound_reg`.
    pub umin: u64,
    pub umax: u64,
    pub s32_min: i32,
    pub s32_max: i32,
    pub u32_min: u32,
    pub u32_max: u32,
}

impl RegBounds {
    /// Build a "no info" bounds — `[s64::MIN, s64::MAX]`, full s32/u32
    /// ranges, not constant. The materializer treats this as the 64-bit-
    /// var fallback (no bound predicates emitted).
    pub fn unknown() -> Self {
        Self {
            const_val: None,
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: u64::MAX,
            s32_min: i32::MIN,
            s32_max: i32::MAX,
            u32_min: 0,
            u32_max: u32::MAX,
        }
    }

    /// Kernel's `fit_u32(reg)` (verifier.c:822). True when the reg's
    /// 64-bit u-range exactly equals its 32-bit u-range — i.e., the value
    /// is provably representable in a u32.
    pub fn fit_u32(&self) -> bool {
        // We don't track u64 bounds explicitly; approximate via the signed
        // interval: when smin >= 0, the u-range equals (smin, smax). It
        // fits in u32 iff that range is contained in [0, u32::MAX] AND
        // matches our 32-bit u-bounds.
        self.smin >= 0
            && self.smax <= u32::MAX as i64
            && self.smin as u64 == self.u32_min as u64
            && self.smax as u64 == self.u32_max as u64
    }

    /// Kernel's `fit_s32(reg)` (verifier.c:828). True when the reg's
    /// 64-bit s-range exactly equals its 32-bit s-range.
    pub fn fit_s32(&self) -> bool {
        self.smin >= i32::MIN as i64
            && self.smax <= i32::MAX as i64
            && self.smin == self.s32_min as i64
            && self.smax == self.s32_max as i64
    }
}

/// Symbolic-tracking state accumulated during BCF refinement.
#[derive(Debug, Clone, Default)]
pub struct SymbolicState {
    /// Expression DAG in declaration order.
    pub exprs: Vec<BcfExpr>,
    /// Total u32 slot count consumed by `exprs` (cached for O(1) `next_idx`).
    next_slot: u32,
    /// Per-register expression index (`None` until materialized).
    pub reg_expr: [Option<u32>; NUM_REGS],
    /// Parallel to `reg_expr`: the PC at which each reg's currently-cached
    /// `bcf_expr` was materialized (either via lazy `reg_expr` first-use,
    /// `bind_reg` from a spill/fill propagation, or any other binder).
    /// `None` iff the reg's bcf_expr is uncached. Used at canonical-hash
    /// time to compute "would this reg be uncached in a fresh kernel
    /// `bcf_track` replay starting at base_pc?" — equivalent to
    /// `reg_expr_pc.is_none() || reg_expr_pc.unwrap() < base_pc`.
    /// The kernel emits `K==K` iff `dst.bcf_pre=-1` at branch time,
    /// i.e. the reg was not materialized within the replay window.
    pub reg_expr_pc: [Option<usize>; NUM_REGS],
    /// Path-condition predicates (each a u32 idx into `exprs`).
    pub path_conds: Vec<u32>,
    /// Parallel to `path_conds`: the source PC at which each predicate was
    /// emitted. Branch path_conds carry the JMP insn's PC. Bound preds
    /// emitted by `bound_reg*` carry the PC at which the reg was first
    /// materialized symbolically. Used by [`filter_path_conds_from_pc`]
    /// at refine time to mirror the kernel's `bcf_track` suffix-only
    /// br_cond emission (verifier.c:24308).
    pub path_cond_pcs: Vec<usize>,
    /// Parallel to `path_conds`: true iff this entry was pushed via
    /// `add_cond_at` (a branch transfer's path-condition; mirrors
    /// kernel's `record_path_cond` push at verifier.c:21117). False iff
    /// pushed by `bound_pred` (mirrors kernel's `bcf_bound_reg`
    /// materialization push at verifier.c:849). Used by
    /// [`filter_path_conds_from_pc`] to identify the "immediate
    /// previous branch" L without confusing it with bound preds.
    pub path_cond_is_branch: Vec<bool>,
    /// Parallel to `path_conds`: when this entry was pushed by a branch
    /// JMP whose narrowing collapses the LHS reg to a const K on the
    /// side that took it, holds `Some((K, op, jmp32, lhs_materialize_pc))`.
    /// The 4th element is the PC at which the LHS reg's bcf_expr was
    /// materialized at branch time (`None` iff LHS was uncached then).
    /// `None` for non-narrowing branches or bound pred pushes.
    ///
    /// At BCF-refinement, the rewrite to `K op K` fires iff in a fresh
    /// kernel `bcf_track` replay starting at `base_pc`, the LHS would
    /// be uncached at this branch — equivalent to
    /// `lhs_materialize_pc.is_none() || lhs_materialize_pc.unwrap() < base_pc`.
    /// Mirrors kernel `record_path_cond` post-`___mark_reg_known`
    /// + fresh-replay semantics (verifier.c:21024 + 2497 + 24536-37).
    pub path_cond_narrowed_const: Vec<Option<(u64, u8, bool, Option<usize>)>>,
    /// Parallel to `path_conds`: when this entry is a branch path_cond
    /// emitted by [`add_cond_at_narrowed`] with a known LHS reg, holds
    /// `Some((lhs_reg_idx, lhs_materialize_pc))`. The reg index is
    /// `Reg::bcf_idx()` (0..NUM_REGS). `lhs_materialize_pc` mirrors the
    /// 4th element of `path_cond_narrowed_const` but is also populated
    /// for NON-narrowing branches (where narrowed_const stays None).
    ///
    /// Used at discharge time for the kernel-mirror per-reg fresh-VAR
    /// rewrite: when `lhs_materialize_pc < base_pc`, the kernel's
    /// `bcf_track` replay re-materializes the LHS reg fresh — assigning
    /// a new bcf_expr distinct from any other reg's. Zovia's live state
    /// may alias the LHS reg's expr with another reg's via spill/fill
    /// propagation; without the rewrite, the canonical hash collapses
    /// two semantically-distinct regs into one VAR.
    ///
    /// `None` for bound preds and branch path_conds whose LHS isn't a
    /// reg-backed scalar (e.g. JSET with non-reg LHS).
    pub path_cond_lhs_meta: Vec<Option<(usize, Option<usize>, bool, RegBounds, RegBounds)>>,
    /// Final refinement condition (set by a site-specific callback).
    pub refine_cond: Option<u32>,
    /// Transient: the PC currently being processed by symbolic-tracking
    /// callbacks. Set by the transfer layer immediately before any
    /// operation that may materialize a register's `bcf_expr` (and
    /// therefore emit bound preds via [`bound_reg32`] / [`bound_reg64`]).
    /// Read by `bound_pred` so bound preds get tagged with the PC at
    /// which lazy materialization happens — mirrors the kernel's
    /// `init_bcf_state` emitting bound preds at the suffix's base PC.
    /// `0` means "untagged" — bound preds with PC=0 are kept regardless
    /// of the filter cutoff, preserving the existing unit-test
    /// behaviour where `SymbolicState` is constructed without PC
    /// context.
    pub current_pc: usize,
    /// VAR→register provenance: maps a `BCF_VAR` expr slot offset to the
    /// register index whose `materialize_reg`/`materialize_reg64` created
    /// it. Populated ONLY at VAR-creation time and never overwritten, so
    /// the recorded reg is the *originating* register even when the VAR
    /// is later shared across registers via mov / spill-fill propagation
    /// (`bind_reg` reuses an existing expr_idx without creating a new
    /// VAR). Const and R10 materializations produce no VAR → no entry.
    ///
    /// Mirrors the kernel's `bcf_reg_expr` data-dependency walk: at a
    /// reject the kernel selects a SMALL register set by recursively
    /// materializing the rejecting comparison's operand regs and their
    /// value-expression dependencies. Reproducing that selection in
    /// zovia's register-filtered discharge requires knowing which reg
    /// each leaf VAR came from.
    pub var_origin: std::collections::HashMap<u32, usize>,
    /// Set true ONLY during a faithful base→reject replay (`reset_for_replay`).
    /// When set, `record_path_cond_for_side` emits the branch operands' CURRENT
    /// (post-narrow) bound preds at each branch — mirroring the kernel's
    /// `bcf_bound_reg` call inside `record_path_cond`, which re-materializes
    /// operand bounds per cond (giving the kernel goal its `u>= K` / duplicate
    /// bound conjuncts). Default false → normal recording/reconstruction unchanged.
    pub replay_emit_bounds: bool,
    /// Replay-scoped (set by `replay_to_reject` slot-share variants only):
    /// the first fill of a spilled non-const scalar whose slot carries no
    /// expr mints the fresh VAR into the SLOT, so every later fill of the
    /// same offset shares it. Mirrors the kernel's `bcf_track` demand
    /// materialization: the backward `bt` walk transfers a reg demand into
    /// the stack slot, the demanded slot materializes ONE var, and each
    /// forward fill carries it via `copy_register_state`
    /// (check_stack_read_fixed_off, verifier.c:5948 — `bcf_expr` copied
    /// verbatim). Default false → all existing emissions byte-stable.
    pub replay_share_slot_vars: bool,
}

impl SymbolicState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset for a faithful base→reject replay: mark every register uncached
    /// (`bcf_expr = -1` in kernel terms) and clear the accumulated path
    /// condition, so the replay re-materializes each register at its first
    /// in-window reference exactly as the kernel's `bcf_track` re-execution
    /// does. The expression ARENA is intentionally KEPT (not cleared): the
    /// base State may still hold bcf-slot references (e.g. spilled stack
    /// slots) into it, and truncating the arena would dangle them. New
    /// materializations append fresh slots; the rebuilt goal only walks
    /// those, so retaining the old (now-unreferenced) slots is harmless.
    pub fn reset_for_replay(&mut self) {
        self.reg_expr = [None; NUM_REGS];
        self.reg_expr_pc = [None; NUM_REGS];
        self.path_conds.clear();
        self.path_cond_pcs.clear();
        self.path_cond_is_branch.clear();
        self.path_cond_narrowed_const.clear();
        self.path_cond_lhs_meta.clear();
        self.refine_cond = None;
        // Mirror the kernel's bcf_track: during replay emit per-branch operand
        // bound preds (bcf_bound_reg) so the goal carries the post-narrow `u>= K`
        // conjuncts the reconstruction's first-ref VAR caching drops.
        self.replay_emit_bounds = true;
    }

    /// Append an expression and return its slot offset.
    pub fn push_expr(&mut self, e: BcfExpr) -> u32 {
        let idx = self.next_slot;
        self.next_slot += e.slot_len();
        self.exprs.push(e);
        idx
    }

    // ---------- value-level builders ----------

    /// Fresh symbolic bitvector variable of `sz` bits.
    pub fn add_var(&mut self, sz: u16) -> u32 {
        self.push_expr(bv_var(sz))
    }
    /// 32-bit constant.
    pub fn add_val32(&mut self, v: u32) -> u32 {
        self.push_expr(bv_val32(v))
    }
    /// 64-bit constant.
    pub fn add_val64(&mut self, v: u64) -> u32 {
        self.push_expr(bv_val64(v))
    }
    /// Binary BV ALU expression at `bits` bitwidth.
    pub fn add_alu(&mut self, op: u8, a: u32, b: u32, bits: u16) -> u32 {
        self.push_expr(bv_alu(op, a, b, bits))
    }
    /// Unary BV ALU expression (vlen=1) at `bits` bitwidth. Mirrors
    /// kernel `bcf_alu`'s `unary` form (verifier.c:15171/15191:
    /// `vlen = unary ? 1 : 2`), used for BPF_NEG.
    pub fn add_unary(&mut self, op: u8, a: u32, bits: u16) -> u32 {
        self.push_expr(BcfExpr {
            code: op | BCF_BV,
            params: bits,
            args: vec![a],
        })
    }
    /// Binary BV predicate (comparison). Result type is Bool.
    pub fn add_pred(&mut self, op: u8, a: u32, b: u32) -> u32 {
        self.push_expr(bv_pred(op, a, b))
    }
    /// Conjunction of boolean preds (≥ 2 args).
    pub fn add_conj(&mut self, args: Vec<u32>) -> u32 {
        self.push_expr(pred_conj(args))
    }
    /// Disjunction of boolean preds (≥ 2 args).
    pub fn add_disj(&mut self, args: Vec<u32>) -> u32 {
        self.push_expr(pred_disj(args))
    }

    /// Unified BV value builder. `bit32 = true` → 32-bit val (vlen=1,
    /// params=32, args=[lo]); `false` → 64-bit val (vlen=2, params=64,
    /// args=[lo, hi]). Mirrors kernel's `bcf_val(env, val, bit32)`
    /// (verifier.c:734).
    pub fn add_val(&mut self, val: u64, bit32: bool) -> u32 {
        if bit32 {
            self.add_val32(val as u32)
        } else {
            self.add_val64(val)
        }
    }

    /// Unified BV variable builder. Mirrors kernel's `bcf_var(env, bit32)`
    /// (verifier.c:747). Use when the register-state width is known; the
    /// width is recorded in `params`.
    pub fn add_var_bits(&mut self, bit32: bool) -> u32 {
        self.add_var(if bit32 { 32 } else { 64 })
    }

    /// General zero/sign-extend builder. Mirrors kernel's `bcf_extend`
    /// (verifier.c:752). `ext_sz` = bits added, `result_width` =
    /// operand_width + ext_sz. params = `(ext_sz << 8) | result_width`.
    /// The kernel's `is_zext_32_to_64` / `is_sext_32_to_64` recognize the
    /// specific (32, 64) form to enable the `bcf_expr32` peel-optimization.
    pub fn add_extend(
        &mut self,
        sign_ext: bool,
        ext_sz: u16,
        result_width: u16,
        arg: u32,
    ) -> u32 {
        let op = if sign_ext { BCF_SIGN_EXTEND } else { BCF_ZERO_EXTEND };
        self.push_expr(BcfExpr {
            code: op | BCF_BV,
            params: (ext_sz << 8) | result_width,
            args: vec![arg],
        })
    }

    /// Extract low `size` bits. Mirrors kernel's `bcf_extract(env, sz, expr)`
    /// (verifier.c:761). `params = (size - 1) << 8` (start=size-1, end=0).
    pub fn add_extract(&mut self, size: u16, arg: u32) -> u32 {
        let start = size.saturating_sub(1);
        self.push_expr(BcfExpr {
            code: BCF_EXTRACT | BCF_BV,
            params: start << 8,
            args: vec![arg],
        })
    }

    /// Zero-extend a 32-bit value to 64 bits. Compatibility shim for the
    /// existing `bcf_alu` mirror code; prefer `add_extend(false, 32, 64, _)`
    /// in new code.
    #[allow(dead_code)]
    pub fn zext_32_to_64(&mut self, arg: u32) -> u32 {
        self.add_extend(false, 32, 64, arg)
    }

    /// Sign-extend a 32-bit value to 64 bits. Compatibility shim.
    #[allow(dead_code)]
    pub fn sext_32_to_64(&mut self, arg: u32) -> u32 {
        self.add_extend(true, 32, 64, arg)
    }

    /// Extract the low `size` bits of `arg`. Compatibility shim that wraps
    /// [`add_extract`]; existing callers may pass `u8` — keep them working.
    #[allow(dead_code)]
    pub fn extract_lo(&mut self, size: u8, arg: u32) -> u32 {
        self.add_extract(size as u16, arg)
    }

    /// Return the 32-bit form of the expression at `slot`. Mirrors the
    /// kernel's `bcf_expr32` (verifier.c:793):
    ///
    /// - If the expression is `ZEXT_32_to_64(x)` or `SEXT_32_to_64(x)`,
    ///   return `x` directly (peel the redundant extend).
    /// - If it's a 64-bit `BV_VAL(lo, hi)`, build and return a fresh
    ///   32-bit `BV_VAL(lo)`.
    /// - Otherwise emit `EXTRACT[31:0]` of `slot`.
    ///
    /// This is the central optimization that keeps kernel-side DAGs lean
    /// and matches the structural shape canonical-hash expects from the
    /// proof emitter.
    pub fn expr32(&mut self, slot: u32) -> u32 {
        // Inspect under immutable borrow first, drop it before mutating.
        let (code, params, first_arg) = {
            if self.expr_at(slot).is_none() && std::env::var("ZOVIA_BCF_REPLAY_DEBUG").is_ok() {
                eprintln!("[expr32-BAD] slot={} next_slot={} n_exprs={} reg_expr={:?}",
                    slot, self.next_slot, self.exprs.len(), self.reg_expr);
            }
            let e = self
                .expr_at(slot)
                .expect("expr32: slot must point at an expr header");
            (e.code, e.params, e.args.first().copied().unwrap_or(0))
        };

        let op = code & BCF_OP_MASK;
        let ty = code & BCF_TYPE_MASK;

        // Peel ZEXT_32_to_64 / SEXT_32_to_64. params = (32<<8)|64 = 0x2040.
        let is_ext_32_to_64 = ty == BCF_BV
            && (op == BCF_ZERO_EXTEND || op == BCF_SIGN_EXTEND)
            && params == ((32u16 << 8) | 64);
        if is_ext_32_to_64 {
            return first_arg;
        }

        // 64-bit BV_VAL → rebuild as 32-bit with the low half.
        if code == (BCF_VAL | BCF_BV) && params == 64 {
            return self.add_val32(first_arg);
        }

        // Generic case: EXTRACT low 32 bits.
        self.add_extract(32, slot)
    }

    // ---------- path conditions / refinement target ----------

    /// Append a path condition (an expression that must hold on the current path).
    /// PC defaults to `self.current_pc` — callers that have explicit source-PC
    /// context should call [`add_cond_at`] instead.
    #[allow(dead_code)]
    pub fn add_cond(&mut self, pred_idx: u32) {
        let pc = self.current_pc;
        self.add_cond_at(pred_idx, pc);
    }

    /// Append a path condition tagged with the source PC. Branch transfer
    /// passes the JMP insn's PC; the [`filter_path_conds_from_pc`] cutoff
    /// drops entries strictly below `base_pc` to mirror the kernel's
    /// `bcf_track` suffix-only br_cond emission.
    #[allow(dead_code)]
    pub fn add_cond_at(&mut self, pred_idx: u32, pc: usize) {
        if std::env::var("ZOVIA_TRACE_PATH_COND").ok().as_deref() == Some("1") {
            let (lo, hi) = std::env::var("ZOVIA_TRACE_PATH_COND_RANGE")
                .ok()
                .and_then(|s| {
                    let mut it = s.split(':');
                    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
                })
                .unwrap_or((0usize, usize::MAX));
            if pc >= lo && pc <= hi {
                eprintln!(
                    "[PATH_COND] push pc={} pred_idx={} (depth_now={}, branch=true)",
                    pc, pred_idx, self.path_conds.len() + 1
                );
            }
        }
        self.path_conds.push(pred_idx);
        self.path_cond_pcs.push(pc);
        self.path_cond_is_branch.push(true);
        self.path_cond_narrowed_const.push(None);
        self.path_cond_lhs_meta.push(None);
    }

    /// Same as [`add_cond_at`] but also records the narrowed-LHS const
    /// metadata (`Some((K, op_byte, jmp32))`) for kernel-mirror rewrite
    /// of `VAR op K` → `K op K` at canonical-hash emission time. Use
    /// when the branch transfer has confirmed LHS narrowed to K on this
    /// side (e.g. JEQ-K taken / JNE-K not-taken). Mirrors kernel
    /// `record_path_cond` post-`___mark_reg_known` semantics.
    ///
    /// `lhs_meta` records the LHS reg index + materialize_pc for the
    /// per-reg fresh-VAR rewrite at discharge time (broader case than
    /// the narrowed-const-only K==K rewrite). Pass `None` when the LHS
    /// isn't a reg-backed scalar or isn't tracked.
    pub fn add_cond_at_narrowed(
        &mut self,
        pred_idx: u32,
        pc: usize,
        narrowed: Option<(u64, u8, bool, Option<usize>)>,
        lhs_meta: Option<(usize, Option<usize>, bool, RegBounds, RegBounds)>,
    ) {
        self.path_conds.push(pred_idx);
        self.path_cond_pcs.push(pc);
        self.path_cond_is_branch.push(true);
        self.path_cond_narrowed_const.push(narrowed);
        self.path_cond_lhs_meta.push(lhs_meta);
    }

    /// Walk the expression tree rooted at `root` and return the set of
    /// BCF_VAR slot offsets it references. Used by the kernel-faithful
    /// `filter_path_conds_from_pc` to decide whether a sub-`base_pc`
    /// path_cond should be kept by virtue of referencing the same
    /// symbolic variables as the "immediate previous branch" cond.
    pub fn collect_vars(&self, root: u32) -> std::collections::HashSet<u32> {
        use crate::refinement::bcf::{BCF_OP_MASK, BCF_VAR};
        let mut vars = std::collections::HashSet::new();
        // The expr table is a DAG with shared subexpressions (the fold reuses
        // VARs; add_alu/add_pred/add_extend reference existing slots), so a
        // plain DFS re-traverses shared nodes EXPONENTIALLY — the stack grows
        // without bound and the walk never terminates on a large fold DAG.
        // Memoize with a visited-set so each node is expanded once:
        // exponential → linear in DAG size.
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![root];
        while let Some(idx) = stack.pop() {
            if !visited.insert(idx) {
                continue;
            }
            let Some(e) = self.expr_at(idx) else { continue };
            if (e.code & BCF_OP_MASK) == BCF_VAR {
                vars.insert(idx);
            }
            for &arg in &e.args {
                stack.push(arg);
            }
        }
        vars
    }

    /// Drop path_conds whose source PC is strictly less than `base_pc`,
    /// matching the kernel's `bcf_track` rule: br_conds are emitted only
    /// during the forward replay of the suffix from base→cur. Entries
    /// with `pc == 0` are treated as "untagged / always present" and are
    /// kept regardless of the cutoff — this preserves unit-test
    /// behaviour for [`SymbolicState`]s constructed without PC context.
    ///
    /// KERNEL-FAITHFUL EXTENSION: in addition to suffix conds
    /// (`source_pc >= base_pc`), also retain the conds the kernel
    /// re-emits via `record_path_cond` + lazy
    /// `bcf_reg_expr`/`bcf_bound_reg` at the FIRST instruction of the
    /// `bcf_track` replay (verifier.c:21112-21120 + 894-926). That entry
    /// corresponds to the immediate previous branch (`prev_insn_idx`)
    /// before the cache event at `base_pc`. We approximate it by:
    ///   1. picking `L` = the path_cond with the LARGEST `source_pc <
    ///      base_pc` (the most recent branch-cond push before the
    ///      cache),
    ///   2. retaining any path_cond whose referenced BCF_VAR set is
    ///      ⊆ vars(L) — this picks up `L` itself plus all bound preds
    ///      pushed for `L`'s variables (mirroring the kernel's lazy
    ///      `bcf_reg_expr` materialization).
    /// Without this, MISS-side emissions drop the upstream conds the
    /// kernel re-pushes at replay-start, so the canonical hash misses
    /// the kernel's expected entry.
    /// Keep exactly the path-cond entries at the given (sorted) indices.
    /// The POSITIONAL analog of `filter_path_conds_from_pc` — the kernel's
    /// `bcf_track` emits br_conds only along the walk suffix from the base
    /// state to cur, which is a recording-order slice, not a pc window
    /// (they differ when the path wraps a loop).
    pub fn retain_path_conds_by_index(&mut self, kept: &[usize]) {
        debug_assert_eq!(self.path_conds.len(), self.path_cond_pcs.len());
        debug_assert_eq!(self.path_conds.len(), self.path_cond_is_branch.len());
        fn take<T: Clone>(v: &mut Vec<T>, kept: &[usize]) {
            let old = std::mem::take(v);
            *v = kept.iter().filter_map(|&i| old.get(i).cloned()).collect();
        }
        take(&mut self.path_conds, kept);
        take(&mut self.path_cond_pcs, kept);
        take(&mut self.path_cond_is_branch, kept);
        take(&mut self.path_cond_narrowed_const, kept);
        take(&mut self.path_cond_lhs_meta, kept);
    }

    pub fn filter_path_conds_from_pc(
        &mut self,
        base_pc: usize,
        prev_insn_pc: Option<usize>,
    ) {
        if base_pc == 0 {
            return;
        }
        debug_assert_eq!(self.path_conds.len(), self.path_cond_pcs.len());
        debug_assert_eq!(self.path_conds.len(), self.path_cond_is_branch.len());

        // KERNEL-FAITHFUL: locate L = the branch cond pushed at source_pc
        // == prev_insn_pc. Mirrors the kernel's `record_path_cond` push
        // at `bcf_track` replay's first instruction (verifier.c:21117),
        // which fires only when the cached base state's immediate
        // predecessor was a scalar conditional branch. Skip if
        // prev_insn_pc is unknown, no path_cond was pushed at exactly
        // that PC, or none of those pushes is a branch (only bound
        // preds). Once L is found, also retain bound preds whose
        // referenced var set is a subset of vars(L) — these are the
        // bound preds the kernel re-emits via `bcf_reg_expr`'s lazy
        // `bcf_bound_reg` at the same site (verifier.c:894-926).
        let l_idx_opt = prev_insn_pc.and_then(|pp| {
            self.path_cond_pcs.iter().enumerate()
                .find(|&(idx, &pc)| pc == pp && self.path_cond_is_branch[idx])
                .map(|(idx, _)| idx)
        });
        let l_vars: std::collections::HashSet<u32> = match l_idx_opt {
            Some(idx) => self.collect_vars(self.path_conds[idx]),
            None => std::collections::HashSet::new(),
        };

        let mut kept_exprs = Vec::with_capacity(self.path_conds.len());
        let mut kept_pcs = Vec::with_capacity(self.path_cond_pcs.len());
        let mut kept_is_branch = Vec::with_capacity(self.path_cond_is_branch.len());
        let mut kept_narrowed = Vec::with_capacity(self.path_cond_narrowed_const.len());
        let mut kept_lhs_meta = Vec::with_capacity(self.path_cond_lhs_meta.len());
        for (idx, &pc) in self.path_cond_pcs.iter().enumerate() {
            let is_branch = self.path_cond_is_branch[idx];
            let keep = pc == 0
                || pc >= base_pc
                // The branch-into-base predicate itself (L at prev_insn_pc).
                // Kernel emits this via `record_path_cond` at the first
                // bcf_track replay step (verifier.c:21155, prev_insn_idx =
                // vstate->last_insn_idx).
                || Some(pc) == prev_insn_pc
                // Bound predicates (is_branch=false) for variables that L
                // operates on. Kernel re-emits these via bcf_reg_expr ->
                // bcf_bound_reg32 when materializing L's operands during
                // replay (verifier.c:894-926, lazy bound emission).
                //
                // Branches (is_branch=true) with source_pc < base_pc are NOT
                // retained — only the literal L (handled above). An
                // unconditional vars-subset rule would transitively pull in
                // EARLIER branches on aliased SSA versions of L's variables.
                || (!is_branch && !l_vars.is_empty() && {
                    let cond_vars = self.collect_vars(self.path_conds[idx]);
                    !cond_vars.is_empty() && cond_vars.is_subset(&l_vars)
                });
            if keep {
                kept_exprs.push(self.path_conds[idx]);
                kept_pcs.push(pc);
                kept_is_branch.push(is_branch);
                kept_narrowed.push(self.path_cond_narrowed_const[idx]);
                kept_lhs_meta.push(self.path_cond_lhs_meta[idx]);
            }
        }
        // If the filter empties the path_cond set, the resulting SMT goal
        // has no constraints and discharge cannot match the kernel's
        // expected hash (kernel always emits at least its branch cond at
        // replay-start). Falling back to "keep all" mirrors the kernel's
        // `base_pc=NULL` behavior when its walker terminates without a
        // kernel-equivalent base. No perturbation of existing matched
        // hashes: the filter still applies whenever it retains anything.
        if kept_exprs.is_empty() && !self.path_conds.is_empty() {
            return;
        }
        self.path_conds = kept_exprs;
        self.path_cond_pcs = kept_pcs;
        self.path_cond_is_branch = kept_is_branch;
        self.path_cond_narrowed_const = kept_narrowed;
        self.path_cond_lhs_meta = kept_lhs_meta;
    }

    /// TRAJECTORY-suffix window filter. Like
    /// [`filter_path_conds_from_pc`] but the window is the maximal
    /// TRAILING run of recorded conds with pc >= base_pc, not every entry
    /// numerically >= base_pc. The kernel's bcf_track replay is a linear
    /// re-execution base→reject of ITS trajectory suffix; when zovia's
    /// path crossed higher-pc code BEFORE the base (subprog call), the
    /// numeric filter wrongly keeps those carried conds and every emitted
    /// form is polluted. Retention of L (prev-push) + its bound preds
    /// mirrors the numeric filter.
    pub fn filter_path_conds_traj_suffix(
        &mut self,
        base_pc: usize,
        prev_insn_pc: Option<usize>,
    ) {
        if base_pc == 0 {
            return;
        }
        let n = self.path_conds.len();
        let mut start = n;
        while start > 0 && self.path_cond_pcs[start - 1] >= base_pc {
            start -= 1;
        }
        let l_idx_opt = prev_insn_pc.and_then(|pp| {
            self.path_cond_pcs.iter().enumerate()
                .find(|&(idx, &pc)| pc == pp && self.path_cond_is_branch[idx])
                .map(|(idx, _)| idx)
        });
        let l_vars: std::collections::HashSet<u32> = match l_idx_opt {
            Some(idx) => self.collect_vars(self.path_conds[idx]),
            None => std::collections::HashSet::new(),
        };
        let mut kept_exprs = Vec::with_capacity(n);
        let mut kept_pcs = Vec::with_capacity(n);
        let mut kept_is_branch = Vec::with_capacity(n);
        let mut kept_narrowed = Vec::with_capacity(n);
        let mut kept_lhs_meta = Vec::with_capacity(n);
        for (idx, &pc) in self.path_cond_pcs.iter().enumerate() {
            let is_branch = self.path_cond_is_branch[idx];
            let keep = idx >= start
                || pc == 0
                || Some(pc) == prev_insn_pc
                || (!is_branch && !l_vars.is_empty() && {
                    let cond_vars = self.collect_vars(self.path_conds[idx]);
                    !cond_vars.is_empty() && cond_vars.is_subset(&l_vars)
                });
            if keep {
                kept_exprs.push(self.path_conds[idx]);
                kept_pcs.push(pc);
                kept_is_branch.push(is_branch);
                kept_narrowed.push(self.path_cond_narrowed_const[idx]);
                kept_lhs_meta.push(self.path_cond_lhs_meta[idx]);
            }
        }
        if kept_exprs.is_empty() && !self.path_conds.is_empty() {
            return;
        }
        self.path_conds = kept_exprs;
        self.path_cond_pcs = kept_pcs;
        self.path_cond_is_branch = kept_is_branch;
        self.path_cond_narrowed_const = kept_narrowed;
        self.path_cond_lhs_meta = kept_lhs_meta;
    }

    /// Register-filtered path_cond selection — mirrors the kernel's
    /// `bcf_reg_expr` data-dependency closure (verifier.c:882). Where
    /// [`filter_path_conds_from_pc`] selects by *source PC* (the suffix
    /// window), this selects by *register*: keep only the branch
    /// path_conds whose LHS register is in `goal_regs`, plus the bound
    /// preds that materialize the VARs those kept branches reference.
    ///
    /// The kernel's reject hash is the canonical hash of a small,
    /// register-filtered conjunction (e.g. `{V0=proto2, V1=tcp}`), not
    /// the full PC-suffix conjunction. zovia's PC-suffix filter pulls in
    /// intervening unrelated-register branches; this restores the clean
    /// subset once a provenance-seeded goal set is known. The goal set is
    /// computed by the caller via VAR→reg provenance (def-use closure).
    ///
    /// Rules:
    /// - branch (is_branch=true) with `path_cond_lhs_meta = Some((reg, …))`:
    ///   keep iff `reg ∈ goal_regs`.
    /// - branch with `path_cond_lhs_meta = None` (e.g. JSET non-reg LHS):
    ///   kept conservatively — dropping it risks losing a load-bearing
    ///   contradiction, and the solver-fallback can't re-add it.
    /// - bound pred (is_branch=false): keep iff its referenced VAR set is
    ///   non-empty and ⊆ the VAR set of the kept branches (the bounds the
    ///   kernel re-emits while materializing those branches' operands).
    ///
    /// Always keeps `pc == 0` (untagged) entries to preserve unit-test
    /// behaviour. If the filter empties the set, falls back to keep-all
    /// (returns without mutating) so discharge still has a goal — matching
    /// [`filter_path_conds_from_pc`]'s empty-guard.
    pub fn filter_path_conds_by_regs(&mut self, goal_regs: &std::collections::HashSet<usize>) {
        debug_assert_eq!(self.path_conds.len(), self.path_cond_lhs_meta.len());
        // Pass 1: decide which branches to keep, and accumulate the VAR
        // set those kept branches reference.
        let mut keep_branch = vec![false; self.path_conds.len()];
        let mut kept_branch_vars: std::collections::HashSet<u32> =
            std::collections::HashSet::new();
        for i in 0..self.path_conds.len() {
            if self.path_cond_pcs[i] == 0 {
                continue; // handled as always-keep in pass 2
            }
            if self.path_cond_is_branch[i] {
                let keep = match self.path_cond_lhs_meta[i] {
                    Some((reg, _, _, _, _)) => goal_regs.contains(&reg),
                    None => true, // non-reg-LHS branch: keep conservatively
                };
                if keep {
                    keep_branch[i] = true;
                    for v in self.collect_vars(self.path_conds[i]) {
                        kept_branch_vars.insert(v);
                    }
                }
            }
        }
        // Pass 2: build the kept vectors. Branches per pass-1 decision;
        // bound preds iff their vars ⊆ kept_branch_vars.
        let mut kept_exprs = Vec::with_capacity(self.path_conds.len());
        let mut kept_pcs = Vec::with_capacity(self.path_conds.len());
        let mut kept_is_branch = Vec::with_capacity(self.path_conds.len());
        let mut kept_narrowed = Vec::with_capacity(self.path_conds.len());
        let mut kept_lhs_meta = Vec::with_capacity(self.path_conds.len());
        for i in 0..self.path_conds.len() {
            let keep = self.path_cond_pcs[i] == 0
                || if self.path_cond_is_branch[i] {
                    keep_branch[i]
                } else {
                    let vars = self.collect_vars(self.path_conds[i]);
                    !vars.is_empty() && vars.is_subset(&kept_branch_vars)
                };
            if keep {
                kept_exprs.push(self.path_conds[i]);
                kept_pcs.push(self.path_cond_pcs[i]);
                kept_is_branch.push(self.path_cond_is_branch[i]);
                kept_narrowed.push(self.path_cond_narrowed_const[i]);
                kept_lhs_meta.push(self.path_cond_lhs_meta[i]);
            }
        }
        // Empty-guard: a register filter that drops everything would
        // produce a constraint-free goal that can never match the
        // kernel's hash. Keep-all in that case (no mutation).
        if kept_exprs.is_empty() && !self.path_conds.is_empty() {
            return;
        }
        self.path_conds = kept_exprs;
        self.path_cond_pcs = kept_pcs;
        self.path_cond_is_branch = kept_is_branch;
        self.path_cond_narrowed_const = kept_narrowed;
        self.path_cond_lhs_meta = kept_lhs_meta;
    }

    /// Provenance-seeded shallow def-use goal-set selection. Mirrors the
    /// kernel `bcf_reg_expr` recursive data-dependency walk to choose the
    /// small register set whose conditions form the reject conjunction.
    ///
    /// Seed = the LHS register of the most-recent branch path_cond (the
    /// immediate-predecessor "rejecting comparison" L, identified by the
    /// largest source PC among branch entries carrying `lhs_meta`). From
    /// the seed, follow `hops` (1–2) edges through the value-expression
    /// DAG: for each reg in the working set, walk its cached `reg_expr`,
    /// and for every leaf VAR it references add that VAR's originating
    /// register (via [`var_origin`]). This pulls in registers that *feed*
    /// the rejecting comparison's value (e.g. proto2 feeding the packet
    /// pointer) without over-connecting to the whole data-flow component.
    ///
    /// Returns `None` when no seed branch exists (no reg-backed branch in
    /// the current path_conds) — the caller then skips register filtering.
    pub fn provenance_goal_set(&self, hops: usize) -> Option<std::collections::HashSet<usize>> {
        // Seed: lhs reg of the branch with the largest source PC that has
        // reg-backed lhs_meta.
        let mut seed_reg: Option<usize> = None;
        let mut seed_pc: Option<usize> = None;
        for i in 0..self.path_conds.len() {
            if !self.path_cond_is_branch[i] {
                continue;
            }
            if let Some((reg, _, _, _, _)) = self.path_cond_lhs_meta[i] {
                let pc = self.path_cond_pcs[i];
                if seed_pc.map(|p| pc >= p).unwrap_or(true) {
                    seed_pc = Some(pc);
                    seed_reg = Some(reg);
                }
            }
        }
        let seed = seed_reg?;
        let mut goal: std::collections::HashSet<usize> = std::collections::HashSet::new();
        goal.insert(seed);
        let mut frontier: Vec<usize> = vec![seed];
        for _ in 0..hops {
            let mut next: Vec<usize> = Vec::new();
            for &r in &frontier {
                if let Some(expr) = self.reg_expr.get(r).copied().flatten() {
                    for v in self.collect_vars(expr) {
                        if let Some(&orig) = self.var_origin.get(&v) {
                            if goal.insert(orig) {
                                next.push(orig);
                            }
                        }
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        Some(goal)
    }

    /// Set the PC tag for subsequently-emitted bound preds via
    /// [`bound_pred`]. Transfer-layer code that triggers lazy register
    /// materialization calls this before the materialization happens, so
    /// bound preds get tagged with the materialization PC.
    pub fn set_current_pc(&mut self, pc: usize) {
        self.current_pc = pc;
    }

    /// Set the refinement condition target.
    pub fn set_refine_cond(&mut self, idx: u32) {
        self.refine_cond = Some(idx);
    }
}

/// Build the per-site refinement goal expression and return its slot.
///
/// Matches the kernel-side BCF goal layout (see `bcf_refine` in
/// kernel/bpf/verifier.c): `CONJ(path_cond_aggregated, refine_cond)` where
/// `path_cond_aggregated` is the single path-cond when there's one, or a
/// flat CONJ over all path-conds when there are several. The kernel's
/// `__expr_equiv` check against the proof's assume-step argument requires
/// this exact structural shape; pointing `goal_root` at just `refine_cond`
/// fails with -EINVAL at bundle prevalidate.
pub fn build_goal_root(sym: &mut SymbolicState, refine_cond: u32) -> u32 {
    match sym.path_conds.len() {
        0 => refine_cond,
        1 => sym.add_conj(vec![sym.path_conds[0], refine_cond]),
        _ => {
            let pcs = sym.path_conds.clone();
            let inner = sym.add_conj(pcs);
            sym.add_conj(vec![inner, refine_cond])
        }
    }
}

impl SymbolicState {

    // ---------- per-register bindings ----------

    /// Bind register `reg` to symbolic expression `idx`. Records the
    /// current PC as the materialization PC (see `reg_expr_pc`); used
    /// at canonical-hash time to decide whether the bind would have
    /// happened inside or outside a fresh kernel `bcf_track` replay
    /// starting at base_pc.
    pub fn bind_reg(&mut self, reg: usize, idx: u32) {
        // ZOVIA_DBG_MAT=1: backtrace the caller of a probed bind.
        if std::env::var("ZOVIA_DBG_MAT").ok().as_deref() == Some("1")
            && reg == 3
            && self.current_pc == 661
        {
            use std::sync::atomic::{AtomicU32, Ordering};
            static B: AtomicU32 = AtomicU32::new(0);
            if B.fetch_add(1, Ordering::Relaxed) < 2 {
                eprintln!("[bind-bt-661] {}", std::backtrace::Backtrace::force_capture());
            }
        }
        self.reg_expr[reg] = Some(idx);
        self.reg_expr_pc[reg] = Some(self.current_pc);
    }

    /// Get the bound expression for `reg`.
    pub fn get_reg(&self, reg: usize) -> Option<u32> {
        self.reg_expr[reg]
    }

    /// Get the PC at which `reg`'s currently-cached `bcf_expr` was
    /// materialized. `None` iff uncached. See `reg_expr_pc` field doc.
    pub fn get_reg_pc(&self, reg: usize) -> Option<usize> {
        self.reg_expr_pc[reg]
    }

    /// Clear the bound expression for `reg` (e.g., before a clobbering write
    /// whose new expression hasn't been built yet). Mirrors BCF's
    /// `reg->bcf_expr = -1` clears.
    pub fn clear_reg(&mut self, reg: usize) {
        self.reg_expr[reg] = None;
        self.reg_expr_pc[reg] = None;
    }

    /// Restore a previously-snapshotted `(expr, materialize_pc)` binding
    /// verbatim (subprog-exit caller-reg restore — kernel `bcf_expr` is
    /// per-frame `bpf_reg_state`; see `CallFrame::caller_bcf_reg_snap`).
    /// Unlike `bind_reg`, does NOT restamp the materialization pc.
    pub fn restore_reg_binding(&mut self, reg: usize, binding: (Option<u32>, Option<usize>)) {
        self.reg_expr[reg] = binding.0;
        self.reg_expr_pc[reg] = binding.1;
    }

    /// Kernel-mirror `bcf_alu` early bail-out (verifier.c:15220-15223):
    /// when an ALU op's post-narrowing value is a known constant, kernel
    /// clears `dst_reg->bcf_expr = -1` and returns without materializing
    /// the expression chain. The next `bcf_reg_expr` call then takes the
    /// `tnum_is_const` branch and emits a pure `bcf_val(K)` literal.
    ///
    /// Without this, downstream branches emit `ZEXT((VAR op K))` chains
    /// for what the kernel materializes as bare `K`, breaking byte-faithful
    /// discharge hashes.
    ///
    /// Returns `true` when the cache was cleared and the caller should
    /// skip ALU-expression materialization (mirrors kernel's `return 0`).
    pub fn clear_reg_if_const(&mut self, reg: usize, bounds: &RegBounds) -> bool {
        if bounds.const_val.is_some() {
            self.clear_reg(reg);
            true
        } else {
            false
        }
    }

    /// Append a typed predicate `op(lhs, val(imm, bit32))` and register it
    /// as a path-condition. Mirrors kernel's `__bcf_bound_reg` →
    /// `bcf_add_cond(bcf_add_pred(...))` chain (verifier.c:834). Tags the
    /// emitted path_cond with `current_pc` so the bcf_track filter at
    /// refine time can decide whether this reg's bound preds are in the
    /// suffix the kernel re-replays.
    fn bound_pred(&mut self, op: u8, lhs: u32, imm: u64, bit32: bool) -> u32 {
        let rhs = self.add_val(imm, bit32);
        let pred = self.add_pred(op, lhs, rhs);
        let pc = self.current_pc;
        if std::env::var("ZOVIA_TRACE_BOUND_PRED").ok().as_deref() == Some("1") {
            let (lo, hi) = std::env::var("ZOVIA_TRACE_BOUND_PRED_RANGE")
                .ok().and_then(|s| {
                    let mut it = s.split(':');
                    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
                }).unwrap_or((0usize, usize::MAX));
            if pc >= lo && pc <= hi {
                eprintln!("[BOUND_PRED] pc={} op=0x{:x} lhs={} imm={} bit32={} pred={}",
                    pc, op, lhs, imm, bit32, pred);
            }
        }
        self.path_conds.push(pred);
        self.path_cond_pcs.push(pc);
        self.path_cond_is_branch.push(false);
        self.path_cond_narrowed_const.push(None);
        self.path_cond_lhs_meta.push(None);
        pred
    }

    /// Public variant of [`bound_reg32`]/[`bound_reg64`] that returns
    /// the emitted bound-pred expr slots WITHOUT pushing them onto
    /// `path_conds`. Used by [`crate::refinement::refine_unreachable`]
    /// to insert bound preds for fresh per-reg VARs at the correct
    /// position in the rewritten path_conds (interleaved with the
    /// branches they materialize for, matching the kernel's
    /// bcf_canonical_hash byte order).
    pub fn bound_reg_emit_preds(&mut self, expr: u32, bounds: &RegBounds, bit32: bool) -> Vec<u32> {
        let mut emitted: Vec<u32> = Vec::new();
        if bit32 {
            let (u32_min, u32_max) = (bounds.u32_min, bounds.u32_max);
            let (s32_min, s32_max) = (bounds.s32_min, bounds.s32_max);
            if u32_min != 0 {
                let rhs = self.add_val(u32_min as u64, true);
                emitted.push(self.add_pred(BPF_JGE, expr, rhs));
            }
            if u32_max != u32::MAX {
                let rhs = self.add_val(u32_max as u64, true);
                emitted.push(self.add_pred(BPF_JLE, expr, rhs));
            }
            if s32_min != i32::MIN && s32_min as u64 != u32_min as u64 {
                let rhs = self.add_val(s32_min as i64 as u64, true);
                emitted.push(self.add_pred(BPF_JSGE, expr, rhs));
            }
            if s32_max != i32::MAX && s32_max as u64 != u32_max as u64 {
                let rhs = self.add_val(s32_max as i64 as u64, true);
                emitted.push(self.add_pred(BPF_JSLE, expr, rhs));
            }
        } else {
            // Mirror kernel `bcf_bound_reg` (verifier.c:873) EXACTLY: emit
            // umin/umax/smin/smax from the reg's INDEPENDENT u64 + s64
            // fields, skipping a signed bound when it equals the unsigned
            // one. The u64 bounds come straight from the domain (no longer
            // derived from `smax`), so a zero-extended index reg with
            // umax=0xffffffff but smax=0x7fffffff yields BOTH preds.
            let (umin, umax) = (bounds.umin, bounds.umax);
            let (smin, smax) = (bounds.smin, bounds.smax);
            if umin != 0 {
                let rhs = self.add_val(umin, false);
                emitted.push(self.add_pred(BPF_JGE, expr, rhs));
            }
            if umax != u64::MAX {
                let rhs = self.add_val(umax, false);
                emitted.push(self.add_pred(BPF_JLE, expr, rhs));
            }
            if smin != i64::MIN && smin as u64 != umin {
                let rhs = self.add_val(smin as u64, false);
                emitted.push(self.add_pred(BPF_JSGE, expr, rhs));
            }
            if smax != i64::MAX && smax as u64 != umax {
                let rhs = self.add_val(smax as u64, false);
                emitted.push(self.add_pred(BPF_JSLE, expr, rhs));
            }
        }
        emitted
    }

    /// 32-bit version of `bound_reg`. Emits umin/umax/smin/smax bound
    /// predicates as path conditions where the reg's known interval is
    /// tighter than the full u32/s32 range. Mirrors kernel's
    /// `bcf_bound_reg32` (verifier.c:840).
    fn bound_reg32(&mut self, expr: u32, bounds: &RegBounds) {
        let (u32_min, u32_max) = (bounds.u32_min, bounds.u32_max);
        let (s32_min, s32_max) = (bounds.s32_min, bounds.s32_max);
        if u32_min != 0 {
            self.bound_pred(BPF_JGE, expr, u32_min as u64, true);
        }
        if u32_max != u32::MAX {
            self.bound_pred(BPF_JLE, expr, u32_max as u64, true);
        }
        if s32_min != i32::MIN && s32_min as u64 != u32_min as u64 {
            self.bound_pred(BPF_JSGE, expr, s32_min as i64 as u64, true);
        }
        if s32_max != i32::MAX && s32_max as u64 != u32_max as u64 {
            self.bound_pred(BPF_JSLE, expr, s32_max as i64 as u64, true);
        }
    }

    /// 64-bit bound predicates. Mirrors kernel's `bcf_bound_reg`
    /// (verifier.c:861). zovia's Domain doesn't track umin/umax directly
    /// for 64-bit, so we approximate from the signed interval when it's
    /// fully non-negative.
    fn bound_reg64(&mut self, expr: u32, bounds: &RegBounds) {
        // Mirror kernel `bcf_bound_reg` (verifier.c:873) EXACTLY: emit from
        // the reg's INDEPENDENT u64 (umin/umax) and s64 (smin/smax) fields,
        // skipping a signed bound when it equals the unsigned one. The u64
        // bounds come straight from the domain's umin_value/umax_value
        // (no longer derived from the signed interval), so a zero-extended
        // jump-table index with umax=0xffffffff but smax=0x7fffffff yields
        // BOTH ULE(reg,0xffffffff) and JSLE(reg,0x7fffffff).
        let (umin, umax) = (bounds.umin, bounds.umax);
        let (smin, smax) = (bounds.smin, bounds.smax);
        if umin != 0 {
            self.bound_pred(BPF_JGE, expr, umin, false);
        }
        if umax != u64::MAX {
            self.bound_pred(BPF_JLE, expr, umax, false);
        }
        if smin != i64::MIN && smin as u64 != umin {
            self.bound_pred(BPF_JSGE, expr, smin as u64, false);
        }
        if smax != i64::MAX && smax as u64 != umax {
            self.bound_pred(BPF_JSLE, expr, smax as u64, false);
        }
    }

    /// Lazy-materialize a register's BCF expression in **kernel-shape**.
    /// Mirrors `bcf_reg_expr(env, reg, subreg)` (verifier.c:882):
    ///
    /// - Const → `BV_VAL(val, 64)`.
    /// - Fits in u32 → `ZEXT_32_to_64(BV_VAR(32))`, with 32-bit bound preds.
    /// - Fits in s32 → `SEXT_32_to_64(BV_VAR(32))`, with 32-bit bound preds.
    /// - Otherwise → `BV_VAR(64)` with 64-bit bound preds.
    ///
    /// **Invariant**: the cached `reg_expr[reg]` slot always holds the
    /// 64-bit form. When `subreg` is `true` the caller wants the 32-bit
    /// form — we re-derive it via [`expr32`], which peels ZEXT/SEXT
    /// trivially when the cache was built via the 32-bit-fits path.
    pub fn reg_expr(&mut self, reg: usize, bounds: &RegBounds, subreg: bool) -> u32 {
        // Fetch-or-materialize the cached 64-bit form.
        let cached = match self.reg_expr[reg] {
            Some(idx) => idx,
            None => {
                let idx = self.materialize_reg(reg, bounds);
                // DIAGNOSIS-ONLY (ZOVIA_DBG_MAT=1): print every VAR
                // materialization with its bounds.
                if std::env::var("ZOVIA_DBG_MAT").ok().as_deref() == Some("1") {
                    eprintln!(
                        "[mat] reg=r{} pc={} const={:?} smin={:#x} smax={:#x} umin={:#x} umax={:#x} s32=[{},{}] u32=[{:#x},{:#x}]",
                        reg, self.current_pc, bounds.const_val,
                        bounds.smin, bounds.smax, bounds.umin, bounds.umax,
                        bounds.s32_min, bounds.s32_max, bounds.u32_min, bounds.u32_max
                    );
                    // One-shot caller identification: print a backtrace
                    // for the first few matching materializations.
                    if reg == 3 && self.current_pc == 661 {
                        use std::sync::atomic::{AtomicU32, Ordering};
                        static M: AtomicU32 = AtomicU32::new(0);
                        if M.fetch_add(1, Ordering::Relaxed) < 2 {
                            eprintln!("[mat-bt-661] {}", std::backtrace::Backtrace::force_capture());
                        }
                    }
                    if reg == 0 && bounds.smin == -4095 {
                        use std::sync::atomic::{AtomicU32, Ordering};
                        static N: AtomicU32 = AtomicU32::new(0);
                        if N.fetch_add(1, Ordering::Relaxed) < 2 {
                            eprintln!("[mat-bt] {}", std::backtrace::Backtrace::force_capture());
                        }
                    }
                }
                self.reg_expr[reg] = Some(idx);
                self.reg_expr_pc[reg] = Some(self.current_pc);
                idx
            }
        };
        if subreg {
            self.expr32(cached)
        } else {
            cached
        }
    }

    /// Build the initial 64-bit cached expression for `reg` according to
    /// the four fit_u32/fit_s32/const cases. Internal helper for
    /// [`reg_expr`]; not for direct use.
    fn materialize_reg(&mut self, reg: usize, bounds: &RegBounds) -> u32 {
        // R10 is the frame pointer with offset 0 from itself — special-case
        // it to a const 0 so stack-pointer arithmetic chains symbolize.
        // This is zovia-specific; the kernel handles R10 via the verifier's
        // ptr-type system instead.
        if reg == 10 {
            return self.add_val64(0);
        }
        if let Some(v) = bounds.const_val {
            return self.add_val64(v);
        }
        // During replay, reg_expr makes a BARE VAR (kernel bcf_reg_expr): the
        // operand bounds come from the per-branch bcf_bound_reg mirror in
        // record_path_cond_for_side. Emitting first-ref bounds here too would
        // DOUBLE the bound conjuncts (over-emit vs the kernel goal).
        // ZOVIA_BCF_REPLAY_FIRSTREF: kernel-faithful FIRST-REF bound emission —
        // bcf_reg_expr→bcf_bound_reg emits a reg's bounds at its FIRST
        // materialization (read OR branch), wherever it is. The deferred
        // (branch-only) REPLAY arm LOSES bounds for regs first-materialized at a
        // non-branch read (bcf_materialize_src) — they become cached bare vars
        // and the arm skips them. With this flag, materialize_reg emits at
        // first-ref and the deferred arm is disabled (see
        // record_path_cond_for_side).
        let replay_firstref =
            crate::common::config::bcf_mirror_knob("ZOVIA_BCF_REPLAY_FIRSTREF", true);
        let emit_first_ref_bounds = !self.replay_emit_bounds || replay_firstref;
        if bounds.fit_u32() {
            let v32 = self.add_var_bits(true);
            self.var_origin.insert(v32, reg);
            if emit_first_ref_bounds {
                self.bound_reg32(v32, bounds);
            }
            return self.add_extend(false, 32, 64, v32);
        }
        if bounds.fit_s32() {
            let v32 = self.add_var_bits(true);
            self.var_origin.insert(v32, reg);
            if emit_first_ref_bounds {
                self.bound_reg32(v32, bounds);
            }
            return self.add_extend(true, 32, 64, v32);
        }
        let v64 = self.add_var_bits(false);
        self.var_origin.insert(v64, reg);
        if emit_first_ref_bounds {
            self.bound_reg64(v64, bounds);
        }
        v64
    }

    /// Lazy-materialize a 64-bit symbolic expression for `reg`.
    /// If already bound, returns the existing index; otherwise allocates a
    /// fresh 64-bit symbolic variable and binds it. Mirrors BCF's
    /// `bcf_reg_expr` entry point — anything that wants `reg` symbolically
    /// goes through here.
    ///
    /// **R10 is special**: it's the frame pointer, and its offset relative
    /// to itself is the constant 0 — not an unknown symbolic value. This
    /// lets pointer-arithmetic chains like `r1 = r10; r1 += -16; r1 += r0`
    /// produce a meaningful symbolic offset expression for r1. Index 10 is
    /// hard-coded to match the `Reg::R10.bcf_idx()` convention.
    ///
    /// Always 64-bit (BCF picks 32 or 64 based on `fit_u32/fit_s32`).
    #[allow(dead_code)]
    pub fn materialize_reg64(&mut self, reg: usize) -> u32 {
        if let Some(idx) = self.reg_expr[reg] {
            return idx;
        }
        let idx = if reg == 10 {
            self.add_val64(0)
        } else {
            let v = self.add_var(64);
            self.var_origin.insert(v, reg);
            v
        };
        self.bind_reg(reg, idx);
        idx
    }

    // ---------- queries ----------

    /// Total expression-table size in u32 slots (matches the on-disk `expr_cnt`).
    #[allow(dead_code)]
    pub fn expr_slot_count(&self) -> u32 {
        self.next_slot
    }

    /// Look up an expression by its slot offset. `None` if not found.
    pub fn expr_at(&self, idx: u32) -> Option<&BcfExpr> {
        let mut cur = 0u32;
        for e in &self.exprs {
            if cur == idx {
                return Some(e);
            }
            cur += e.slot_len();
        }
        None
    }

    /// Build a [`BcfProof`] artifact whose `exprs` is the current DAG and whose
    /// `steps` is empty. Useful for serializing the formula (without a proof
    /// yet) — e.g., to hash it canonically or feed it to an SMT-LIB encoder.
    #[allow(dead_code)]
    pub fn to_proof_no_steps(&self) -> BcfProof {
        BcfProof {
            exprs: self.exprs.clone(),
            steps: vec![],
        }
    }
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    /// The basic shape of a SymbolicState: expressions accumulate by slot offset,
    /// not by Vec index.
    #[test]
    fn slot_offsets_account_for_arg_arrays() {
        let mut s = SymbolicState::new();
        let v = s.add_var(64); // 1 slot
        assert_eq!(v, 0);
        let c = s.add_val64(0xdead_beef_cafe_babe); // 1 + 2 = 3 slots
        assert_eq!(c, 1);
        let a = s.add_alu(BPF_ADD, v, c, 64); // 1 + 2 = 3 slots
        assert_eq!(a, 4);
        assert_eq!(s.expr_slot_count(), 7);
    }

    /// `expr_at` finds entries by slot offset, not by Vec index.
    #[test]
    fn expr_at_lookup() {
        let mut s = SymbolicState::new();
        let v = s.add_var(64);
        let c = s.add_val64(42);
        let a = s.add_alu(BPF_ADD, v, c, 64);
        assert_eq!(s.expr_at(v).unwrap().code, BCF_VAR | BCF_BV);
        assert_eq!(s.expr_at(c).unwrap().code, BCF_VAL | BCF_BV);
        assert_eq!(s.expr_at(a).unwrap().code, BPF_ADD | BCF_BV);
        assert!(s.expr_at(99).is_none());
    }

    /// `add_val(bit32)` should match the explicit 32/64 builders byte-exact.
    #[test]
    fn add_val_dispatch() {
        let mut s = SymbolicState::new();
        let v32 = s.add_val(0xdead_beef, true);
        let v64 = s.add_val(0x1234_5678_9abc_def0, false);
        let v32_ref = s.add_val32(0xdead_beef);
        let v64_ref = s.add_val64(0x1234_5678_9abc_def0);
        assert_eq!(s.expr_at(v32).unwrap(), s.expr_at(v32_ref).unwrap());
        assert_eq!(s.expr_at(v64).unwrap(), s.expr_at(v64_ref).unwrap());
    }

    /// `add_extend(false, 32, 64, _)` is the canonical "ZEXT 32→64" with
    /// params=0x2040, matching the kernel's `bcf_extend` (verifier.c:752).
    #[test]
    fn add_extend_32_to_64_params() {
        let mut s = SymbolicState::new();
        let v = s.add_var(32);
        let z = s.add_extend(false, 32, 64, v);
        let e = s.expr_at(z).unwrap();
        assert_eq!(e.code, BCF_ZERO_EXTEND | BCF_BV);
        assert_eq!(e.params, 0x2040, "ZEXT 32→64 must encode (ext_sz=32)<<8 | (width=64)");
        let v2 = s.add_var(32);
        let sx = s.add_extend(true, 32, 64, v2);
        let e2 = s.expr_at(sx).unwrap();
        assert_eq!(e2.code, BCF_SIGN_EXTEND | BCF_BV);
        assert_eq!(e2.params, 0x2040);
    }

    /// `expr32` peels `ZEXT_32_to_64(x)` straight to `x` (kernel's
    /// `is_zext_32_to_64` short-circuit, verifier.c:793).
    #[test]
    fn expr32_peels_zext_32_to_64() {
        let mut s = SymbolicState::new();
        let v = s.add_var(32);
        let z = s.add_extend(false, 32, 64, v);
        let peeled = s.expr32(z);
        assert_eq!(peeled, v, "expr32 of ZEXT_32_to_64(v) should be v itself");
    }

    /// `expr32` peels `SEXT_32_to_64(x)` straight to `x` as well.
    #[test]
    fn expr32_peels_sext_32_to_64() {
        let mut s = SymbolicState::new();
        let v = s.add_var(32);
        let sx = s.add_extend(true, 32, 64, v);
        assert_eq!(s.expr32(sx), v);
    }

    /// `expr32` does NOT peel a non-32→64 extend (e.g., a 16→32 ZEXT). We'd
    /// have to EXTRACT to get the 32-bit form.
    #[test]
    fn expr32_does_not_peel_non_32_to_64_extend() {
        let mut s = SymbolicState::new();
        let v = s.add_var(16);
        let z16_to_32 = s.add_extend(false, 16, 32, v);
        let result = s.expr32(z16_to_32);
        // Should NOT equal v (no peel) and should be an EXTRACT of z16_to_32.
        let e = s.expr_at(result).unwrap();
        assert_eq!(e.code, BCF_EXTRACT | BCF_BV);
        assert_eq!(e.args, vec![z16_to_32]);
    }

    /// `expr32` of a 64-bit BV_VAL rebuilds it as a 32-bit BV_VAL with the
    /// low 32 bits. Kernel does the same in `bcf_expr32`.
    #[test]
    fn expr32_rebuilds_val64_as_val32() {
        let mut s = SymbolicState::new();
        let v64 = s.add_val64(0x1234_5678_9abc_def0);
        let v32_slot = s.expr32(v64);
        let e = s.expr_at(v32_slot).unwrap();
        assert_eq!(e.code, BCF_VAL | BCF_BV);
        assert_eq!(e.params, 32);
        assert_eq!(e.args, vec![0x9abc_def0]);
    }

    /// Generic case: `expr32` of a 64-bit AND emits an EXTRACT.
    #[test]
    fn expr32_extracts_generic_64bit() {
        let mut s = SymbolicState::new();
        let v = s.add_var(64);
        let c = s.add_val64(0xff);
        let and64 = s.add_alu(BPF_AND, v, c, 64);
        let lo32 = s.expr32(and64);
        let e = s.expr_at(lo32).unwrap();
        assert_eq!(e.code, BCF_EXTRACT | BCF_BV);
        assert_eq!(e.params, 0x1f00, "EXTRACT[31:0] params = (start=31)<<8 | end=0");
        assert_eq!(e.args, vec![and64]);
    }

    /// `fit_u32` recognises a reg constrained to [0, 0xff] as fitting in u32.
    #[test]
    fn fit_u32_for_byte_range() {
        let b = RegBounds {
            const_val: None,
            smin: 0,
            smax: 0xff,
            umin: 0,
            umax: 0xff,
            s32_min: 0,
            s32_max: 0xff,
            u32_min: 0,
            u32_max: 0xff,
        };
        assert!(b.fit_u32());
        assert!(b.fit_s32());
    }

    /// A reg with `smin = -1` is not u32-fitting (negative values escape).
    #[test]
    fn fit_u32_rejects_negative() {
        let b = RegBounds {
            const_val: None,
            smin: -1,
            smax: 100,
            umin: 0,
            umax: u64::MAX,
            s32_min: -1,
            s32_max: 100,
            u32_min: 0,
            u32_max: u32::MAX,
        };
        assert!(!b.fit_u32());
        assert!(b.fit_s32());
    }

    /// `reg_expr` on a constant materializes `BV_VAL(v, 64)` and caches it.
    #[test]
    fn reg_expr_const_caches() {
        let mut s = SymbolicState::new();
        let b = RegBounds {
            const_val: Some(0xdead_beef),
            smin: 0xdead_beef,
            smax: 0xdead_beef,
            umin: 0xdead_beef,
            umax: 0xdead_beef,
            s32_min: i32::MIN,
            s32_max: i32::MAX,
            u32_min: 0,
            u32_max: u32::MAX,
        };
        let e1 = s.reg_expr(0, &b, false);
        let e2 = s.reg_expr(0, &b, false);
        assert_eq!(e1, e2, "second call must hit the cache");
        let exp = s.expr_at(e1).unwrap();
        assert_eq!(exp.code, BCF_VAL | BCF_BV);
        assert_eq!(exp.params, 64);
        assert_eq!(exp.args[0], 0xdead_beef);
        assert_eq!(exp.args[1], 0);
    }

    /// `reg_expr` for a u32-fitting reg emits ZEXT(BV_VAR_32) and bound
    /// predicates. `subreg=true` retrieves the underlying 32-bit form via
    /// `expr32`'s ZEXT-peel.
    #[test]
    fn reg_expr_u32_fits_emits_zext_and_peels_to_var32() {
        let mut s = SymbolicState::new();
        let b = RegBounds {
            const_val: None,
            smin: 0,
            smax: 0xff,
            umin: 0,
            umax: 0xff,
            s32_min: 0,
            s32_max: 0xff,
            u32_min: 0,
            u32_max: 0xff,
        };
        let e64 = s.reg_expr(0, &b, false);
        let e32 = s.reg_expr(0, &b, true);
        // 64-bit form is the ZEXT.
        let e = s.expr_at(e64).unwrap();
        assert_eq!(e.code, BCF_ZERO_EXTEND | BCF_BV);
        assert_eq!(e.params, 0x2040);
        // 32-bit form must be the BV_VAR_32 directly (peeled ZEXT).
        let v32 = s.expr_at(e32).unwrap();
        assert_eq!(v32.code, BCF_VAR | BCF_BV);
        assert_eq!(v32.params, 32);
        // Bound predicates were emitted as path conditions.
        // smax=0xff means a JLE(_, 0xff, true) predicate.
        assert!(
            !s.path_conds.is_empty(),
            "u32 bounds should emit a JLE path-cond"
        );
    }

    /// Two `reg_expr(reg, ..., subreg=true)` calls must return the same
    /// slot — i.e., `expr32` is also idempotent given the cache.
    #[test]
    fn reg_expr_subreg_is_stable() {
        let mut s = SymbolicState::new();
        let b = RegBounds {
            const_val: None,
            smin: 0,
            smax: 100,
            umin: 0,
            umax: 100,
            s32_min: 0,
            s32_max: 100,
            u32_min: 0,
            u32_max: 100,
        };
        let a = s.reg_expr(1, &b, true);
        let b2 = s.reg_expr(1, &b, true);
        assert_eq!(
            a, b2,
            "subreg retrieval should re-peel from cached ZEXT to same slot"
        );
    }

    /// R10 is special: always materializes as BV_VAL(0, 64) regardless of
    /// the bounds passed in. Mirrors zovia's existing `materialize_reg64`.
    #[test]
    fn reg_expr_r10_is_const_zero() {
        let mut s = SymbolicState::new();
        let b = RegBounds::unknown();
        let r10 = s.reg_expr(10, &b, false);
        let e = s.expr_at(r10).unwrap();
        assert_eq!(e.code, BCF_VAL | BCF_BV);
        assert_eq!(e.params, 64);
        assert_eq!(e.args, vec![0, 0]);
    }

    /// Bound predicates: a tight u32 range produces exactly two bound
    /// preds (JGE for umin, JLE for umax) when both differ from defaults.
    #[test]
    fn bound_reg32_emits_expected_preds() {
        let mut s = SymbolicState::new();
        let b = RegBounds {
            const_val: None,
            smin: 5,
            smax: 100,
            umin: 5,
            umax: 100,
            s32_min: 5,
            s32_max: 100,
            u32_min: 5,
            u32_max: 100,
        };
        s.reg_expr(0, &b, false);
        // Expected: JGE(_, 5, true), JLE(_, 100, true) — 2 preds.
        // smin/smax preds skipped because they coincide with umin/umax.
        assert_eq!(s.path_conds.len(), 2);
        let p0 = s.expr_at(s.path_conds[0]).unwrap();
        let p1 = s.expr_at(s.path_conds[1]).unwrap();
        // First should be JGE (BPF_JGE), second JLE.
        assert_eq!(p0.code, BPF_JGE | BCF_BOOL);
        assert_eq!(p1.code, BPF_JLE | BCF_BOOL);
    }

    /// Reconstruct shift_constraint's symbolic state along the unsafe path
    /// (pc 1 → pc 8, with the fall-through of `if r1 > 4` taken). Build the
    /// refinement condition for the stack access at pc 8.
    ///
    /// Program (from `examples/src/shift_constraint.bpf.c`, summarised):
    /// ```text
    /// pc 0: r0 = helper(7)                  // tracepoint arg
    /// pc 1: r0 &= 0xff (32-bit)             // r0 ∈ [0, 255]
    /// pc 2: r1 = r0                         // mov
    /// pc 3: r2 = r10
    /// pc 4: r2 = r10 + (-16)                // stack offset = -16
    /// pc 5: r2 = r2 + r0                    // stack offset = -16 + r0
    /// pc 6: r1 = r1 >> 1                    // r1 = r0 >> 1
    /// pc 7: if r1 > 4 goto 10               // fall-through ⇒ r1 ≤ 4
    /// pc 8: load u8 [r2]                    // STACK ACCESS — rejected by us
    /// pc 9: r0 = 0
    /// pc 10: exit
    /// ```
    ///
    /// Refinement-condition shape (per cheat sheet §4a/§4b): the access at
    /// `r2 = r10 + off` with `off = -16 + r0` and access size 1 is safe iff
    /// `off ∈ [stack_min, -1]` (stack frame is below r10). We encode the OOB
    /// claim — `(off s> -1)` — and want cvc5 to prove the conjunction
    /// `path_conds ∧ refine_cond` unsat.
    #[test]
    fn build_shift_constraint_refinement_formula() {
        let mut s = SymbolicState::new();

        // pc 0–1: r0 originates from a helper return, then masked with 0xff in
        // 32-bit ALU. Modeling as: r0 = zext_32_to_64(sym32 & 0xff).
        let sym32 = s.add_var(32);
        let mask32 = s.add_val32(0xff);
        let masked32 = s.add_alu(BPF_AND, sym32, mask32, 32);
        let r0 = s.zext_32_to_64(masked32);
        s.bind_reg(0, r0);

        // pc 2: r1 = r0 (full mov shares the expression).
        s.bind_reg(1, r0);

        // pc 4–5: r2 represents the stack offset (-16 + r0). We don't
        // symbolically track r10 itself; the offset is what gates safety.
        let neg16 = s.add_val64((-16_i64) as u64);
        let off = s.add_alu(BPF_ADD, neg16, r0, 64);
        s.bind_reg(2, off);

        // pc 6: r1 = r1 >> 1 (ALU64). r1 = r0 >> 1.
        let one64 = s.add_val64(1);
        let r1_shifted = s.add_alu(BPF_RSH, r0, one64, 64);
        s.bind_reg(1, r1_shifted);

        // pc 7 fall-through: r1 ≤ 4. Encoded as r1 JLE 4.
        let four64 = s.add_val64(4);
        let p_fall = s.add_pred(BPF_JLE, r1_shifted, four64);
        s.add_cond(p_fall);

        // Refinement target: prove the access is in bounds. We assert the OOB
        // condition (off s> -1, i.e., off as signed is non-negative for a
        // stack offset that must be ≤ -1) and want unsat.
        let neg1 = s.add_val64((-1_i64) as u64);
        let oob = s.add_pred(BPF_JSGT, off, neg1);
        s.set_refine_cond(oob);

        // ---- structural sanity ----
        assert_eq!(s.path_conds.len(), 1);
        assert!(s.refine_cond.is_some());
        assert!(s.reg_expr[0].is_some());
        assert!(s.reg_expr[1].is_some());
        assert!(s.reg_expr[2].is_some());

        // ---- self-consistency: slot counts and on-disk size ----
        let proof = s.to_proof_no_steps();
        let bytes = proof.to_bytes();
        // Header (12 bytes) + 4 * expr_slot_count + 0 step bytes.
        let expected = 12 + 4 * s.expr_slot_count() as usize;
        assert_eq!(bytes.len(), expected);

        // ---- round-trip through ser/de ----
        let parsed = BcfProof::from_bytes(&bytes).expect("parse failed");
        assert_eq!(parsed.exprs.len(), s.exprs.len());
        assert_eq!(parsed.to_bytes(), bytes);

        // ---- spot-check: the recorded path-cond is a JLE BV predicate ----
        // BV predicates have boolean result type, so code = op | BCF_BOOL.
        let p_expr = s.expr_at(p_fall).unwrap();
        assert_eq!(p_expr.code, BPF_JLE | BCF_BOOL);
        let p_args = &p_expr.args;
        assert_eq!(p_args.len(), 2);
        assert_eq!(p_args[0], r1_shifted);
        assert_eq!(p_args[1], four64);

        // ---- spot-check: the refine-cond is JSGT off > -1 ----
        let r_expr = s.expr_at(oob).unwrap();
        assert_eq!(r_expr.code, BPF_JSGT | BCF_BOOL);
        assert_eq!(r_expr.args[0], off);
        assert_eq!(r_expr.args[1], neg1);
    }
}
