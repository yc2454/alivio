//! Path-unreachable speculation site.
//!
//! Mirrors BCF's `bcf_prove_unreachable` (cheat-sheet §4d). Called from
//! [`crate::analysis::transfer`] at points where zovia accepts natively
//! but the kernel verifier would reject and emit a path-unreachable
//! BCF request — currently only the Mov-from-NotInit case for
//! `unreachable_arsh` (paper §unreachable-arsh).
//!
//! The goal expression is `CONJ(path_conds...)` — no positive-bounds
//! `refine_cond`. cvc5 must prove the conjunction unsatisfiable; on
//! success, the bundle entry is kind=`BCF_BUNDLE_KIND_UNREACHABLE`
//! and the kernel matches it via `bcf_bundle_try_discharge`'s
//! path_cond fallback (commit 39f5104ed029).

use crate::analysis::machine::state::State;
use crate::refinement::smtlib;
use crate::refinement::solver;
use crate::refinement::symbolic::{RegBounds, SymbolicState};
use log::{debug, warn};

/// Returned on success: the goal-root expr-id and the symbolic-state
/// snapshot whose `exprs` table the goal lives in, plus the proof bytes.
pub struct UnreachableOk {
    pub proof_bytes: Vec<u8>,
    pub goal_root: u32,
    pub sym: SymbolicState,
}

/// Attempt to speculatively discharge a kernel-rejection site by proving
/// that `path_cond` is unsatisfiable. The bundle entry's `cond_hash`
/// equals the canonical hash of the goal expression; the kernel
/// `bcf_bundle_try_discharge` path-cond fallback computes the same hash
/// when it reaches the corresponding `bcf_prove_unreachable` site.
///
/// Returns `Some(UnreachableOk)` if cvc5 returned `unsat`; `None` otherwise.
/// `base_pc` is the suffix base PC (analogous to `try_refine_*`); pass
/// `None` to keep all accumulated path_conds.
pub fn try_prove_unreachable(
    state: &State,
    base_pc: Option<usize>,
    prev_insn_pc: Option<usize>,
) -> Option<UnreachableOk> {
    try_prove_unreachable_inner(
        state,
        base_pc,
        prev_insn_pc,
        true,
        None,
        false,
        None,
        None,
        false,
    )
}

// Per-call fold-mode override so a caller can emit BOTH fold forms of the
// same obligation. The kernel folds a reg iff ITS state knows the const at
// the site; whichever form it computes, one of our two variants hash-matches.
thread_local! {
    static FOLD_OVERRIDE: std::cell::Cell<Option<bool>> =
        const { std::cell::Cell::new(None) };
    // When set, the window filter is the TRAJECTORY-suffix rule
    // (filter_path_conds_traj_suffix) instead of the numeric pc rule —
    // mirrors the kernel's linear base→reject replay when zovia's path
    // crossed higher-pc code before the base. ADDITIVE via union modes.
    static TRAJ_SUFFIX: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Trajectory-suffix window variants of [`try_prove_unreachable`] — same
/// fold modes as the plain calls, but the base window is the TRAILING run
/// of recorded conds (kernel replay order), not the numeric pc filter.
/// ADDITIVE; caller dedups by cond_hash.
pub fn try_prove_unreachable_traj(
    state: &State,
    base_pc: Option<usize>,
    prev_insn_pc: Option<usize>,
) -> Option<UnreachableOk> {
    TRAJ_SUFFIX.with(|c| c.set(true));
    let r = try_prove_unreachable_inner(
        state,
        base_pc,
        prev_insn_pc,
        true,
        None,
        false,
        None,
        None,
        false,
    );
    TRAJ_SUFFIX.with(|c| c.set(false));
    r
}

pub fn try_prove_unreachable_traj_fold_legacy(
    state: &State,
    base_pc: Option<usize>,
    prev_insn_pc: Option<usize>,
) -> Option<UnreachableOk> {
    TRAJ_SUFFIX.with(|c| c.set(true));
    FOLD_OVERRIDE.with(|c| c.set(Some(false)));
    let r = try_prove_unreachable_inner(
        state,
        base_pc,
        prev_insn_pc,
        true,
        None,
        false,
        None,
        None,
        false,
    );
    FOLD_OVERRIDE.with(|c| c.set(None));
    TRAJ_SUFFIX.with(|c| c.set(false));
    r
}

pub fn try_prove_unreachable_traj_no_rewrite(
    state: &State,
    base_pc: Option<usize>,
    prev_insn_pc: Option<usize>,
) -> Option<UnreachableOk> {
    TRAJ_SUFFIX.with(|c| c.set(true));
    let r = try_prove_unreachable_inner(
        state,
        base_pc,
        prev_insn_pc,
        false,
        None,
        false,
        None,
        None,
        false,
    );
    TRAJ_SUFFIX.with(|c| c.set(false));
    r
}

/// Legacy-fold variant of [`try_prove_unreachable`]: forces the pre-
/// faithful-fold pipeline (K==K rewrite + per-reg fresh-VAR Class-B) for
/// this one emission. ADDITIVE; caller dedups by cond_hash.
pub fn try_prove_unreachable_fold_legacy(
    state: &State,
    base_pc: Option<usize>,
    prev_insn_pc: Option<usize>,
) -> Option<UnreachableOk> {
    FOLD_OVERRIDE.with(|c| c.set(Some(false)));
    let r = try_prove_unreachable_inner(
        state,
        base_pc,
        prev_insn_pc,
        true,
        None,
        false,
        None,
        None,
        false,
    );
    FOLD_OVERRIDE.with(|c| c.set(None));
    r
}

/// Register-filtered discharge: like [`try_prove_unreachable`] but, after
/// the base_pc suffix filter, also restricts the path_conds to a small
/// register set computed via VAR→reg provenance def-use closure (mirrors
/// the kernel's `bcf_reg_expr` data-dependency selection). This produces
/// the kernel's multi-register reject conjunctions that the PC-suffix
/// filter alone cannot isolate.
///
/// Returns `None` when no provenance seed exists (no reg-backed branch in
/// the suffix) — the caller falls back to the unfiltered discharges.
/// Emitted ADDITIVELY by the caller and deduped by `cond_hash`; never
/// replaces the unfiltered discharge (which keeps already-matched hashes
/// byte-stable).
/// `hops` controls the provenance def-use closure depth (1 → seed + its
/// direct value-deps; 2 → one more layer). PC-independent: selects over
/// the FULL trajectory, since the kernel's bcf_reg_expr materializes a
/// register's recorded condition regardless of how far back it was
/// emitted. Live default-on (see caller in branch/mod.rs).
pub fn try_prove_unreachable_reg_filtered(state: &State, hops: usize) -> Option<UnreachableOk> {
    try_prove_unreachable_inner(
        state,
        None,
        None,
        true,
        Some(hops),
        false,
        None,
        None,
        false,
    )
}

/// Register-filtered discharge with the per-reg fresh-VAR rewrite
/// disabled (mirror of [`try_prove_unreachable_no_rewrite`]).
pub fn try_prove_unreachable_reg_filtered_no_rewrite(
    state: &State,
    hops: usize,
) -> Option<UnreachableOk> {
    try_prove_unreachable_inner(
        state,
        None,
        None,
        false,
        Some(hops),
        false,
        None,
        None,
        false,
    )
}

/// Like [`try_prove_unreachable`] but with the per-reg fresh-VAR rewrite
/// disabled. Used by the chain emission loop to ALSO push the
/// un-rewritten (aliased-VAR) form, so previously-matched hashes (that
/// the kernel may query via its `bcf_track` replay on this specific
/// reject site) stay in the bundle alongside the kernel-shape rewrites.
/// Without this, the rewrite is destructive for any program whose
/// previously-matched hash happens to be the aliased form.
pub fn try_prove_unreachable_no_rewrite(
    state: &State,
    base_pc: Option<usize>,
    prev_insn_pc: Option<usize>,
) -> Option<UnreachableOk> {
    try_prove_unreachable_inner(
        state,
        base_pc,
        prev_insn_pc,
        false,
        None,
        false,
        None,
        None,
        false,
    )
}

/// Kernel `bcf_track` replay-fold, shared by the unreachable-class and
/// refine_map goal paths. See the block comment below for the 3-way
/// bcf_reg_expr mirror semantics.
pub(crate) fn faithful_fold_pass(sym: &mut SymbolicState, base_pc: Option<usize>) {
    // Faithful bcf_reg_expr replay-fold. Single forward pass over
    // path_conds (already in suffix order). For each scalar↔const
    // branch with reg-backed LHS, apply the kernel's 3-way
    // bcf_reg_expr decision keyed on a per-reg cache:
    //   - reg already materialized in THIS pass → reuse its VAR
    //     (`VAR op K`, no new bounds) — mirrors kernel's cached-expr
    //     return at verifier.c:905;
    //   - else if reg is a known constant → fold LHS to `bcf_val(K)`
    //     literal (`Klhs op K`), no VAR, no bounds — mirrors the
    //     `tnum_is_const → bcf_val` path at 910-912;
    //   - else → fresh VAR + bound preds from the @branch range
    //     snapshot, spliced BEFORE the branch (kernel order), cache it.
    // Bound preds (is_branch=false) and non-reg-LHS branches pass
    // through. Original LHS VARs of rewritten/folded branches are
    // collected as orphaned and their now-dangling bound preds dropped.
    use std::collections::{HashMap, HashSet};
    // Key the per-reg materialization cache by (reg, materialize_pc)
    // instead of reg alone, so a reg REDEFINED between two suffix
    // references gets a FRESH VAR per incarnation — mirroring the kernel
    // resetting reg->bcf_expr=-1 on every def (verifier.c bcf_reg_expr).
    // Value = (natural-form expr slot, nat_is_64): a 64-bit-materialized
    // reg caches its 64-bit VAR and EXTRACTs for a jmp32 compare; a
    // 32-bit-fit reg caches its branch-width var (legacy).
    let mut fresh_var_for_reg: HashMap<(usize, Option<usize>), (u32, bool)> = HashMap::new();
    let mut newly_orphaned: HashSet<u32> = HashSet::new();
    let mut new_conds: Vec<u32> = Vec::with_capacity(sym.path_conds.len() + 8);
    let mut new_pcs: Vec<usize> = Vec::with_capacity(sym.path_conds.len() + 8);
    let mut new_is_branch: Vec<bool> = Vec::with_capacity(sym.path_conds.len() + 8);
    let mut new_narrowed: Vec<Option<(u64, u8, bool, Option<usize>)>> =
        Vec::with_capacity(sym.path_conds.len() + 8);
    let mut new_lhs_meta: Vec<Option<(usize, Option<usize>, bool, RegBounds, RegBounds)>> =
        Vec::with_capacity(sym.path_conds.len() + 8);
    let path_conds_snapshot = sym.path_conds.clone();
    let pcs_snapshot = sym.path_cond_pcs.clone();
    let is_branch_snapshot = sym.path_cond_is_branch.clone();
    let narrowed_snapshot = sym.path_cond_narrowed_const.clone();
    let lhs_meta_snapshot = sym.path_cond_lhs_meta.clone();
    for i in 0..path_conds_snapshot.len() {
        let pred_slot = path_conds_snapshot[i];
        let pc = pcs_snapshot[i];
        let is_branch = is_branch_snapshot[i];
        let narrowed = narrowed_snapshot[i];
        let lhs_meta = lhs_meta_snapshot[i];
        // Only branches with a reg-backed scalar LHS are foldable.
        let Some((lhs_reg, lhs_pc, jmp32, lhs_bounds, pre_bounds)) = lhs_meta else {
            new_conds.push(pred_slot);
            new_pcs.push(pc);
            new_is_branch.push(is_branch);
            new_narrowed.push(narrowed);
            new_lhs_meta.push(lhs_meta);
            continue;
        };
        if !is_branch {
            new_conds.push(pred_slot);
            new_pcs.push(pc);
            new_is_branch.push(is_branch);
            new_narrowed.push(narrowed);
            new_lhs_meta.push(lhs_meta);
            continue;
        }
        // Extract (op, arg0=lhs, arg1=rhs) from the predicate expr.
        let (op_with_class, arg0, arg1) = match sym.expr_at(pred_slot) {
            Some(e) if e.args.len() == 2 => (e.code, e.args[0], e.args[1]),
            _ => {
                new_conds.push(pred_slot);
                new_pcs.push(pc);
                new_is_branch.push(is_branch);
                new_narrowed.push(narrowed);
                new_lhs_meta.push(lhs_meta);
                continue;
            }
        };
        let op = op_with_class & crate::refinement::bcf::BCF_OP_MASK;
        // Old LHS var refs become orphaned once we swap the LHS.
        for v in sym.collect_vars(arg0) {
            newly_orphaned.insert(v);
        }
        // PRE-NARROW materialization: the kernel's bcf_reg_expr
        // materializes a reg at its FIRST reference using the range as of
        // ENTERING that insn — i.e. BEFORE the branch's own narrowing.
        // zovia's `lhs_bounds` is post-narrow (the taken side), so a reg
        // narrowed to a const by its own first-reference branch would
        // wrongly fold to a `K op K` literal; the pre-narrow range keeps
        // it a VAR{bound} the kernel-faithful way. Mirrors kernel
        // bcf_reg_expr first-reference-range semantics.
        let prenarrow_on = true;
        // In-suffix branches (pc ≥ base) materialize the reg AT their own
        // branch, so they use the range ENTERING it — PRE-narrow
        // `pre_bounds` — mirroring kernel bcf_reg_expr, which runs before
        // reg_set_min_max narrows (the branch's own narrowing is the
        // recorded COND, not a bound pred). Carried conds (pc < base)
        // reflect the reg's FINAL narrowed range carried into the suffix
        // → post-narrow `lhs_bounds`. NB: a cond whose narrowing is
        // pre-window in the kernel but in-window under zovia's wider
        // replay window cannot be served by this per-branch rule — that
        // requires replay-base placement, not a pre/post toggle.
        let use_pre = prenarrow_on && base_pc.map(|bp| pc >= bp).unwrap_or(false);
        let mat_bounds = if use_pre { &pre_bounds } else { &lhs_bounds };
        // Re-mint cache key: under the flag, key by (reg, materialize_pc)
        // so a redefined reg (call/reload between references) gets a fresh
        // VAR per incarnation (kernel resets reg->bcf_expr on def). Flag
        // off → reg-only key (legacy behaviour).
        let key = if prenarrow_on {
            (lhs_reg, lhs_pc)
        } else {
            (lhs_reg, None)
        };
        if let Some(&(fv, nat_is_64)) = fresh_var_for_reg.get(&key) {
            // CACHED: reuse the reg's already-materialized VAR. A 64-bit
            // natural form is EXTRACTed for a jmp32 compare (kernel
            // bcf_reg_expr → expr32 of the cached 64-bit expr).
            let cmp = if nat_is_64 && jmp32 {
                sym.expr32(fv)
            } else {
                fv
            };
            let new_pred = sym.add_pred(op, cmp, arg1);
            new_conds.push(new_pred);
        } else if let Some(kval) = mat_bounds.const_val {
            // UNCACHED + const (at first-reference range): fold LHS to a
            // bcf_val literal (kernel's tnum_is_const → bcf_val path).
            let lit = sym.add_val(kval, jmp32);
            let new_pred = sym.add_pred(op, lit, arg1);
            new_conds.push(new_pred);
        } else if mat_bounds.fit_u32() || mat_bounds.fit_s32() {
            // UNCACHED + fits 32: legacy path — branch-width VAR + bounds.
            // (Kernel's VAR_U32/VAR_S32 peels to a 32-bit var under a
            // jmp32 compare, matching add_var_bits(jmp32) here.)
            let fresh = sym.add_var_bits(jmp32);
            fresh_var_for_reg.insert(key, (fresh, false));
            let bound_pred_slots = sym.bound_reg_emit_preds(fresh, mat_bounds, jmp32);
            for bp in bound_pred_slots {
                new_conds.push(bp);
                new_pcs.push(pc);
                new_is_branch.push(false);
                new_narrowed.push(None);
                new_lhs_meta.push(None);
            }
            let new_pred = sym.add_pred(op, fresh, arg1);
            new_conds.push(new_pred);
        } else {
            // UNCACHED + non-const + high bits set: the reg does NOT fit
            // u32/s32, so the kernel materializes a 64-BIT VAR (bcf_var
            // (false)) with 64-bit bound-preds and EXTRACTs [31:0] for a
            // jmp32 compare (verifier.c bcf_reg_expr VAR_64 path).
            let v64 = sym.add_var_bits(false);
            fresh_var_for_reg.insert(key, (v64, true));
            let bound_pred_slots = sym.bound_reg_emit_preds(v64, mat_bounds, false);
            for bp in bound_pred_slots {
                new_conds.push(bp);
                new_pcs.push(pc);
                new_is_branch.push(false);
                new_narrowed.push(None);
                new_lhs_meta.push(None);
            }
            let cmp = if jmp32 { sym.expr32(v64) } else { v64 };
            let new_pred = sym.add_pred(op, cmp, arg1);
            new_conds.push(new_pred);
        }
        new_pcs.push(pc);
        new_is_branch.push(true);
        new_narrowed.push(narrowed);
        new_lhs_meta.push(lhs_meta);
    }
    sym.path_conds = new_conds;
    sym.path_cond_pcs = new_pcs;
    sym.path_cond_is_branch = new_is_branch;
    sym.path_cond_narrowed_const = new_narrowed;
    sym.path_cond_lhs_meta = new_lhs_meta;
    // Drop bound preds whose only-referenced VARs are now orphaned
    // (the original live-state VARs replaced by fresh VARs / folds).
    if !newly_orphaned.is_empty() {
        let mut kept_conds = Vec::with_capacity(sym.path_conds.len());
        let mut kept_pcs = Vec::with_capacity(sym.path_conds.len());
        let mut kept_is_branch = Vec::with_capacity(sym.path_conds.len());
        let mut kept_narrowed = Vec::with_capacity(sym.path_conds.len());
        let mut kept_lhs_meta = Vec::with_capacity(sym.path_conds.len());
        for i in 0..sym.path_conds.len() {
            let drop = !sym.path_cond_is_branch[i] && {
                let vars = sym.collect_vars(sym.path_conds[i]);
                !vars.is_empty() && vars.is_subset(&newly_orphaned)
            };
            if !drop {
                kept_conds.push(sym.path_conds[i]);
                kept_pcs.push(sym.path_cond_pcs[i]);
                kept_is_branch.push(sym.path_cond_is_branch[i]);
                kept_narrowed.push(sym.path_cond_narrowed_const[i]);
                kept_lhs_meta.push(sym.path_cond_lhs_meta[i]);
            }
        }
        sym.path_conds = kept_conds;
        sym.path_cond_pcs = kept_pcs;
        sym.path_cond_is_branch = kept_is_branch;
        sym.path_cond_narrowed_const = kept_narrowed;
        sym.path_cond_lhs_meta = kept_lhs_meta;
    }
}

fn try_prove_unreachable_inner(
    state: &State,
    base_pc: Option<usize>,
    prev_insn_pc: Option<usize>,
    do_fresh_var_rewrite: bool,
    reg_filter_hops: Option<usize>,
    loop_suffix: bool,
    // Flag-skip mode: None = off. Some(usize::MAX) = auto (first post-loop
    // foldable branch). Some(pc) = anchor at that specific foldable branch pc
    // (used by the multi-anchor enumerator to emit one obligation per proto
    // arm's flag-clear route).
    flag_skip_anchor: Option<usize>,
    // Loop-entry mode: Some(header_pc) = anchor at a loop-header branch on the
    // ZERO-iteration route (loop ran 0 times), keep pc>=header + rematerialize,
    // NO fold (keep the recorded `0 u>= ...` bound check the kernel keeps).
    loop_entry_anchor: Option<usize>,
    // When loop_entry: also fold the anchor bound-check to the literal `K op K`
    // (using its LHS const), giving the kernel's const-bound `0 u>= 0` form.
    // cvc5 self-validates: on a symbolic-bound route the fold drops the
    // `X==0` constraint so the goal is no longer unsat → not emitted.
    loop_entry_fold: bool,
) -> Option<UnreachableOk> {
    let bcf_ref = state.bcf.as_ref()?;
    let mut sym: SymbolicState = (**bcf_ref).clone();

    // Mirror bcf_track's suffix-only emission: drop path_conds emitted
    // strictly before the suffix base. `prev_insn_pc` enables the
    // kernel's `record_path_cond`-at-replay-start mechanism: if the
    // cached base state's immediate predecessor (vstate->last_insn_idx)
    // was a scalar conditional branch, that branch's cond + its var's
    // bound preds get retained even when their source_pc < base_pc.
    // Register-filtered vs PC-suffix-filtered selection are MUTUALLY
    // EXCLUSIVE axes. PC-suffix (`base_pc`) keeps conds by source PC,
    // mirroring the kernel's bcf_track suffix replay. Register-filtering
    // (`reg_filter_hops`) keeps conds by register over the FULL trajectory,
    // mirroring the kernel's bcf_reg_expr data-dependency closure — it must
    // see conditions arbitrarily far back (e.g. proto2 ~500 PCs before the
    // reject), so it deliberately skips the PC filter.
    match reg_filter_hops {
        None => {
            if let Some(bp) = base_pc {
                if TRAJ_SUFFIX.with(|c| c.get()) {
                    sym.filter_path_conds_traj_suffix(bp, prev_insn_pc);
                } else {
                    sym.filter_path_conds_from_pc(bp, prev_insn_pc);
                }
            }
        }
        Some(hops) => {
            // Provenance-seeded goal set over the full trajectory: seed =
            // most-recent branch's lhs reg, then `hops` def-use layers via
            // VAR→reg provenance. None ⇒ no reg-backed branch ⇒ skip (the
            // caller's unfiltered discharges already cover this anchor).
            match sym.provenance_goal_set(hops) {
                Some(goal) => {
                    if std::env::var("ZOVIA_DUMP_DISCHARGE").ok().as_deref() == Some("1") {
                        let pre = sym.path_conds.len();
                        sym.filter_path_conds_by_regs(&goal);
                        let mut g: Vec<usize> = goal.into_iter().collect();
                        g.sort_unstable();
                        eprintln!(
                            "[disc-regsel] hops={} goal={:?} path_conds {}→{}",
                            hops,
                            g,
                            pre,
                            sym.path_conds.len()
                        );
                    } else {
                        sym.filter_path_conds_by_regs(&goal);
                    }
                }
                None => return None,
            }
        }
    }

    // Kernel-mirror K==K rewrite: for each branch path_cond that narrowed
    // its LHS to a const K on the taken side, substitute the predicate
    // expression with a fresh `K op K` literal. Mirrors kernel
    // `bcf_track`'s fresh-replay where `bcf_reg_expr` re-materializes
    // the dst via `tnum_is_const → bcf_val(K)` because the replay starts
    // with `bcf_expr = -1`.
    //
    // Done as a graph rewrite (add fresh exprs, swap path_cond slot)
    // rather than a full per-replay rebuild so existing cvc5 contradictions
    // via spill/fill-propagated vars stay intact. The fallback below
    // catches cases where K==K substitution removes a load-bearing
    // constraint — falls back to the un-rewritten form and re-runs cvc5,
    // preserving discharge soundness at the cost of byte-match for that
    // specific entry.
    debug_assert_eq!(sym.path_conds.len(), sym.path_cond_narrowed_const.len());
    let original_path_conds = sym.path_conds.clone();
    // Faithful bcf_reg_expr fold. When set, REPLACE the legacy K==K +
    // per-reg fresh-VAR passes with a single forward pass that mirrors
    // the kernel's bcf_reg_expr 3-way decision exactly (cached→reuse VAR
    // / uncached+const→bcf_val literal / uncached+non-const→fresh
    // VAR+bounds), processing path_conds in suffix order so the per-reg
    // cache (`fresh_var_for_reg`) reproduces the kernel's
    // first-materialize-and-cache. Default ON: this fn only runs with a
    // BCF symbolic state present. FOLD_OVERRIDE(false) selects the legacy
    // fold for the additive both-folds emission variant.
    let faithful_fold = FOLD_OVERRIDE.with(|c| c.get()).unwrap_or(true);
    let mut orphaned_vars: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for i in 0..sym.path_conds.len() {
        if faithful_fold {
            break;
        }
        if let Some((k, op_byte, jmp32, lhs_pc)) = sym.path_cond_narrowed_const[i] {
            // Rewrite gate: in a fresh kernel `bcf_track` replay starting
            // at base_pc, the LHS reg's bcf_expr is uncached iff it had
            // never been materialized OR its previous materialization was
            // before base_pc (invisible in the fresh expr table). Skip
            // rewrite if LHS was cached at or after base_pc — kernel
            // would have returned the cached var and emitted `VAR op K`,
            // preserving the binding constraint needed for cvc5 to prove
            // the overall formula unsat (e.g. a const cached via
            // spill/fill propagation pairing with an earlier `!=K` for
            // the contradiction). Conservatively rewrite when base_pc is
            // unknown (mirrors kernel's `base_pc=NULL` keep-all
            // behavior).
            let lhs_uncached_in_fresh_replay = match (lhs_pc, base_pc) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(p), Some(bp)) => p < bp,
            };
            if !lhs_uncached_in_fresh_replay {
                continue;
            }
            // Collect the OLD pred's VAR references before overwriting —
            // these vars are now orphaned in this discharge's canonical
            // encoding (kernel's fresh replay emits `bcf_val(K)` directly
            // and never materializes the VAR, so its bound preds don't
            // exist in kernel's bcf graph). Below we drop matching bound
            // preds from the filtered path_conds for byte-faithful hash.
            let old_pred = sym.path_conds[i];
            for v in sym.collect_vars(old_pred) {
                orphaned_vars.insert(v);
            }
            let lhs = sym.add_val(k, jmp32);
            let rhs = sym.add_val(k, jmp32);
            let new_pred = sym.add_pred(op_byte, lhs, rhs);
            sym.path_conds[i] = new_pred;
        }
    }
    // Drop bound-pred path_conds whose only VAR references are now
    // orphaned by the K==K rewrites above. Mirrors kernel's
    // fresh-replay behavior: when `bcf_reg_expr` takes the
    // `tnum_is_const → bcf_val(K)` path (no `bcf_bound_reg32` call),
    // no bound preds exist for that VAR in the kernel's bcf graph.
    // Zovia inherits the bound preds from its full-trace bcf state
    // (kept by `filter_path_conds_from_pc`'s subset rule for vars(L)),
    // but after we rewrite L to `K op K`, those bound preds become
    // canonical-hash garbage (extra conjuncts kernel doesn't have).
    // Drop only true bound preds (is_branch=false) — branches always
    // stay regardless of var orphanage.
    if !orphaned_vars.is_empty() {
        let mut kept_conds = Vec::with_capacity(sym.path_conds.len());
        let mut kept_pcs = Vec::with_capacity(sym.path_cond_pcs.len());
        let mut kept_is_branch = Vec::with_capacity(sym.path_cond_is_branch.len());
        let mut kept_narrowed = Vec::with_capacity(sym.path_cond_narrowed_const.len());
        let mut kept_lhs_meta = Vec::with_capacity(sym.path_cond_lhs_meta.len());
        for i in 0..sym.path_conds.len() {
            let drop = !sym.path_cond_is_branch[i] && {
                let vars = sym.collect_vars(sym.path_conds[i]);
                !vars.is_empty() && vars.is_subset(&orphaned_vars)
            };
            if !drop {
                kept_conds.push(sym.path_conds[i]);
                kept_pcs.push(sym.path_cond_pcs[i]);
                kept_is_branch.push(sym.path_cond_is_branch[i]);
                kept_narrowed.push(sym.path_cond_narrowed_const[i]);
                kept_lhs_meta.push(sym.path_cond_lhs_meta[i]);
            }
        }
        sym.path_conds = kept_conds;
        sym.path_cond_pcs = kept_pcs;
        sym.path_cond_is_branch = kept_is_branch;
        sym.path_cond_narrowed_const = kept_narrowed;
        sym.path_cond_lhs_meta = kept_lhs_meta;
    }

    if do_fresh_var_rewrite && !faithful_fold {
        // Per-reg fresh-VAR rewrite: mirror kernel's bcf_track fresh-replay
        // where bcf_reg_expr(R) materializes a fresh VAR (plus bound preds)
        // for each reg whose bcf_pre=-1. Generalizes the K==K rewrite above
        // to non-narrowing branches. Inserts bound preds for the fresh VAR
        // immediately BEFORE the branch they materialize for — matches
        // kernel order, since bcf_canonical_hash is position-sensitive
        // within CONJ.
        //
        // ADDITIVE in safety: produces additional canonical-hash bytes
        // for non-narrowing branches; rewritten goals are equi-unsat with
        // the originals (fresh VARs are unconstrained symbolic substitutes
        // for the bounds-narrowed cached exprs). Solver-fallback path
        // below catches any cases where the rewrite weakens unsat.
        {
            use std::collections::HashMap;
            let mut fresh_var_for_reg: HashMap<usize, u32> = HashMap::new();
            let mut newly_orphaned: std::collections::HashSet<u32> =
                std::collections::HashSet::new();
            // New path_conds list, built in original index order with
            // bound preds inserted at materialization sites.
            let mut new_conds: Vec<u32> = Vec::with_capacity(sym.path_conds.len() + 8);
            let mut new_pcs: Vec<usize> = Vec::with_capacity(sym.path_cond_pcs.len() + 8);
            let mut new_is_branch: Vec<bool> =
                Vec::with_capacity(sym.path_cond_is_branch.len() + 8);
            let mut new_narrowed: Vec<Option<(u64, u8, bool, Option<usize>)>> =
                Vec::with_capacity(sym.path_cond_narrowed_const.len() + 8);
            let mut new_lhs_meta: Vec<Option<(usize, Option<usize>, bool, RegBounds, RegBounds)>> =
                Vec::with_capacity(sym.path_cond_lhs_meta.len() + 8);
            let path_conds_snapshot = sym.path_conds.clone();
            let pcs_snapshot = sym.path_cond_pcs.clone();
            let is_branch_snapshot = sym.path_cond_is_branch.clone();
            let narrowed_snapshot = sym.path_cond_narrowed_const.clone();
            let lhs_meta_snapshot = sym.path_cond_lhs_meta.clone();
            for i in 0..path_conds_snapshot.len() {
                let pred_slot = path_conds_snapshot[i];
                let pc = pcs_snapshot[i];
                let is_branch = is_branch_snapshot[i];
                let narrowed = narrowed_snapshot[i];
                let lhs_meta = lhs_meta_snapshot[i];
                // Decide whether to rewrite this entry.
                let do_rewrite = is_branch
                    && narrowed
                        .map(|n| {
                            // K==K already handled (skip if it would have fired)
                            !match (n.3, base_pc) {
                                (None, _) => true,
                                (Some(_), None) => false,
                                (Some(p), Some(bp)) => p < bp,
                            }
                        })
                        .unwrap_or(true)
                    && lhs_meta.is_some();
                if do_rewrite {
                    let (lhs_reg, lhs_pc, jmp32, lhs_bounds, _pre_bounds) = lhs_meta.unwrap();
                    let lhs_uncached_in_fresh_replay = match (lhs_pc, base_pc) {
                        (None, _) => true,
                        (Some(_), None) => false,
                        (Some(p), Some(bp)) => p < bp,
                    };
                    if lhs_uncached_in_fresh_replay {
                        let (op_with_class, arg0, arg1) = {
                            let Some(e) = sym.expr_at(pred_slot) else {
                                new_conds.push(pred_slot);
                                new_pcs.push(pc);
                                new_is_branch.push(is_branch);
                                new_narrowed.push(narrowed);
                                new_lhs_meta.push(lhs_meta);
                                continue;
                            };
                            if e.args.len() != 2 {
                                new_conds.push(pred_slot);
                                new_pcs.push(pc);
                                new_is_branch.push(is_branch);
                                new_narrowed.push(narrowed);
                                new_lhs_meta.push(lhs_meta);
                                continue;
                            }
                            (e.code, e.args[0], e.args[1])
                        };
                        for v in sym.collect_vars(arg0) {
                            newly_orphaned.insert(v);
                        }
                        // First time seeing this reg → allocate fresh VAR
                        // AND emit its bound preds (mirroring kernel's
                        // bcf_reg_expr → bcf_bound_reg sequence).
                        let (fresh, emit_bounds) = match fresh_var_for_reg.get(&lhs_reg) {
                            Some(&v) => (v, false),
                            None => {
                                let v = sym.add_var_bits(jmp32);
                                fresh_var_for_reg.insert(lhs_reg, v);
                                (v, true)
                            }
                        };
                        if emit_bounds {
                            // Use bound_reg_kernel_shape: routes to the
                            // 32-bit or 64-bit emitter and returns the
                            // emitted pred slots so we can splice them
                            // into the new path_conds list at the right
                            // position (BEFORE the branch).
                            let bound_pred_slots =
                                sym.bound_reg_emit_preds(fresh, &lhs_bounds, jmp32);
                            for bp_slot in bound_pred_slots {
                                new_conds.push(bp_slot);
                                new_pcs.push(pc);
                                new_is_branch.push(false);
                                new_narrowed.push(None);
                                new_lhs_meta.push(None);
                            }
                        }
                        let op = op_with_class & crate::refinement::bcf::BCF_OP_MASK;
                        let new_pred = sym.add_pred(op, fresh, arg1);
                        new_conds.push(new_pred);
                        new_pcs.push(pc);
                        new_is_branch.push(true);
                        new_narrowed.push(narrowed);
                        new_lhs_meta.push(lhs_meta);
                        continue;
                    }
                }
                // Default: pass through unmodified.
                new_conds.push(pred_slot);
                new_pcs.push(pc);
                new_is_branch.push(is_branch);
                new_narrowed.push(narrowed);
                new_lhs_meta.push(lhs_meta);
            }
            sym.path_conds = new_conds;
            sym.path_cond_pcs = new_pcs;
            sym.path_cond_is_branch = new_is_branch;
            sym.path_cond_narrowed_const = new_narrowed;
            sym.path_cond_lhs_meta = new_lhs_meta;
            // Drop bound preds whose only-referenced VARs are now orphaned.
            if !newly_orphaned.is_empty() {
                let mut kept_conds = Vec::with_capacity(sym.path_conds.len());
                let mut kept_pcs = Vec::with_capacity(sym.path_cond_pcs.len());
                let mut kept_is_branch = Vec::with_capacity(sym.path_cond_is_branch.len());
                let mut kept_narrowed = Vec::with_capacity(sym.path_cond_narrowed_const.len());
                let mut kept_lhs_meta = Vec::with_capacity(sym.path_cond_lhs_meta.len());
                for i in 0..sym.path_conds.len() {
                    let drop = !sym.path_cond_is_branch[i] && {
                        let vars = sym.collect_vars(sym.path_conds[i]);
                        !vars.is_empty() && vars.is_subset(&newly_orphaned)
                    };
                    if !drop {
                        kept_conds.push(sym.path_conds[i]);
                        kept_pcs.push(sym.path_cond_pcs[i]);
                        kept_is_branch.push(sym.path_cond_is_branch[i]);
                        kept_narrowed.push(sym.path_cond_narrowed_const[i]);
                        kept_lhs_meta.push(sym.path_cond_lhs_meta[i]);
                    }
                }
                sym.path_conds = kept_conds;
                sym.path_cond_pcs = kept_pcs;
                sym.path_cond_is_branch = kept_is_branch;
                sym.path_cond_narrowed_const = kept_narrowed;
                sym.path_cond_lhs_meta = kept_lhs_meta;
            }
        }
    } // end do_fresh_var_rewrite

    if do_fresh_var_rewrite && faithful_fold {
        faithful_fold_pass(&mut sym, base_pc);
    }

    if std::env::var("ZOVIA_BCF_DUMP_PATH_COND_PCS").is_ok() {
        // Build slot→record-index map (path_conds/args hold SLOTS, exprs is
        // record-indexed; slot advances by slot_len() per record).
        let mut slot_to_idx: std::collections::HashMap<u32, usize> =
            std::collections::HashMap::new();
        {
            let mut s: u32 = 0;
            for (i, e) in sym.exprs.iter().enumerate() {
                slot_to_idx.insert(s, i);
                s += e.slot_len();
            }
        }
        let get = |slot: u32| {
            sym.exprs
                .get(*slot_to_idx.get(&slot).unwrap_or(&usize::MAX))
        };
        // Decode each path_cond predicate to (reg, op, const) + source_pc.
        let resolve = |mut slot: u32| -> String {
            for _ in 0..12 {
                let Some(e) = get(slot) else {
                    return format!("e{slot}");
                };
                let base = e.code & 0xf8;
                if base == 0x18 {
                    return match sym.var_origin.get(&slot) {
                        Some(r) => format!("r{r}"),
                        None => format!("V{slot}"),
                    };
                } else if base == 0x08 {
                    return format!("0x{:x}", e.args.first().copied().unwrap_or(0));
                } else if !e.args.is_empty() {
                    slot = e.args[0];
                } else {
                    return format!("e{slot}");
                }
            }
            format!("e{slot}")
        };
        eprintln!(
            "[bcf] PATHCOND-DUMP base_pc={:?} n={}",
            base_pc,
            sym.path_conds.len()
        );
        for (i, (&cond, &pc)) in sym
            .path_conds
            .iter()
            .zip(sym.path_cond_pcs.iter())
            .enumerate()
        {
            let isb = sym.path_cond_is_branch.get(i).copied().unwrap_or(false);
            let (lhs, op, rhs) = match get(cond) {
                Some(e) if e.args.len() >= 2 => (resolve(e.args[0]), e.code, resolve(e.args[1])),
                Some(e) => ("?".into(), e.code, "?".into()),
                None => ("?".into(), 0, "?".into()),
            };
            eprintln!("  [{i:>2}] pc={pc:<5} {lhs} op=0x{op:02x} {rhs}  br={isb}");
        }
    }

    if sym.path_conds.is_empty() {
        debug!("[bcf] path-unreachable: no path_conds accumulated, nothing to prove");
        return None;
    }

    // Loop-suffix-base discharge variant. Emitted ADDITIVELY by the caller
    // alongside the normal discharge (deduped by hash), so it can only ADD
    // the kernel's post-loop obligation, never drop another reject's.
    // When the reject's recorded path crossed a bounded loop, zovia (which
    // unrolls it) accumulates one cond per iteration at the loop's back-edge
    // insn — e.g. 31× `r8!=32` (loop-back) + 31× `r8<r1` (continue) + the exit
    // `r8==32`. The kernel's bcf_track base is the LOOP EXIT (back-edge src+1):
    // its replay never re-executes the loop, so only the exit branch (32==32)
    // and the post-loop suffix survive. Detect the unrolled loop from the conds
    // (a BRANCH source-pc that REPEATS == a back-edge), anchor at exit = max
    // such pc + 1: keep pc>=exit plus EXACTLY the LAST branch at the back-edge
    // pc (the exit eval). No-op when no source-pc repeats.
    if loop_suffix {
        use std::collections::HashMap;
        let mut branch_pc_count: HashMap<usize, usize> = HashMap::new();
        for i in 0..sym.path_cond_pcs.len() {
            if sym.path_cond_is_branch[i] {
                *branch_pc_count.entry(sym.path_cond_pcs[i]).or_insert(0) += 1;
            }
        }
        let src = branch_pc_count
            .iter()
            .filter(|&(_pc, &c)| c > 1)
            .map(|(&pc, _)| pc)
            .max();
        match src {
            None => return None, // no unrolled loop → nothing this variant adds
            Some(src) => {
                let exit = src + 1;
                let last_at_src = (0..sym.path_cond_pcs.len())
                    .rev()
                    .find(|&i| sym.path_cond_pcs[i] == src && sym.path_cond_is_branch[i]);
                let n = sym.path_conds.len();
                let mut kc = Vec::with_capacity(n);
                let mut kp = Vec::with_capacity(n);
                let mut kb = Vec::with_capacity(n);
                let mut kn = Vec::with_capacity(n);
                let mut km = Vec::with_capacity(n);
                for i in 0..n {
                    let pc = sym.path_cond_pcs[i];
                    if pc == 0 || pc >= exit || Some(i) == last_at_src {
                        kc.push(sym.path_conds[i]);
                        kp.push(pc);
                        kb.push(sym.path_cond_is_branch[i]);
                        kn.push(sym.path_cond_narrowed_const[i]);
                        km.push(sym.path_cond_lhs_meta[i]);
                    }
                }
                if kc.is_empty() || kc.len() == n {
                    return None; // filter changed nothing → no distinct variant
                }
                if std::env::var("ZOVIA_DUMP_DISCHARGE").ok().as_deref() == Some("1") {
                    eprintln!(
                        "[loop-suffix-base] src={} exit={} conds {}->{}",
                        src,
                        exit,
                        n,
                        kc.len()
                    );
                }
                sym.path_conds = kc;
                sym.path_cond_pcs = kp;
                sym.path_cond_is_branch = kb;
                sym.path_cond_narrowed_const = kn;
                sym.path_cond_lhs_meta = km;
            }
        }
    }

    // Flag-skip-base discharge variant.
    // Like loop-suffix-base, but advance the anchor PAST the loop exit to the
    // FIRST narrowed-const (foldable EQ-taken / NE-taken) branch after it.
    // Typical shape: a "flag" branch `If R1==0 -> ...`
    // where R1 was just masked `R1 &= 1024` to {0,1024}: on the flag-CLEAR
    // (==0) trajectory R1 pins to 0, so the existing K==K / faithful fold has
    // already rewritten that cond to `0==0`. Re-anchoring there drops the loop
    // AND the flag's `!=0x400` conjunct, leaving `0==0` + the post-flag
    // suffix — the kernel's flag-bypass obligation that the loop-suffix
    // (which keeps the flag as `!=0x400`) and pre-loop base_pc discharges miss.
    // ADDITIVE + deduped by the caller; returns None when there's no loop or no
    // post-loop foldable branch, so it never drops another reject's obligation.
    if let Some(fs_anchor) = flag_skip_anchor {
        use std::collections::HashMap;
        let mut branch_pc_count: HashMap<usize, usize> = HashMap::new();
        for i in 0..sym.path_cond_pcs.len() {
            if sym.path_cond_is_branch[i] {
                *branch_pc_count.entry(sym.path_cond_pcs[i]).or_insert(0) += 1;
            }
        }
        // loop exit = max repeated branch source-pc + 1 (same back-edge
        // detection as loop-suffix). No unrolled loop → nothing to add.
        let exit = match branch_pc_count
            .iter()
            .filter(|&(_pc, &c)| c > 1)
            .map(|(&pc, _)| pc)
            .max()
        {
            None => return None,
            Some(src) => src + 1,
        };
        // Pick the anchor: a post-exit branch carrying a narrowed-const fold
        // (the `0==0` base on a flag-clear side). usize::MAX = auto (first
        // such); otherwise anchor at exactly the requested pc (multi-anchor
        // enumerator, one obligation per proto arm's flag-clear route).
        let ai = (0..sym.path_cond_pcs.len()).find(|&i| {
            sym.path_cond_is_branch[i]
                && sym.path_cond_pcs[i] >= exit
                && sym.path_cond_narrowed_const[i].is_some()
                && (fs_anchor == usize::MAX || sym.path_cond_pcs[i] == fs_anchor)
        })?;
        let anchor_pc = sym.path_cond_pcs[ai];
        // Fold the anchor branch to the literal `K op K` (e.g. `0 == 0` on the
        // flag-clear side where R1 pinned to 0). The kernel's fresh bcf_track
        // replay starting AT this branch sees the masked reg as tnum-const and
        // emits `bcf_val(K)` directly (no cached VAR) — so its obligation has
        // the folded literal, not `VAR op K`. zovia's FAITHFUL_FOLD keeps the
        // reg cached (materialized at the mask insn just before), so we fold it
        // here explicitly to match. Done BEFORE collecting kept_branch_vars so
        // the now-orphaned reg VAR's bound preds drop out (kernel has none).
        if let Some((k, op_byte, jmp32, _lhs_pc)) = sym.path_cond_narrowed_const[ai] {
            let lhs = sym.add_val(k, jmp32);
            let rhs = sym.add_val(k, jmp32);
            sym.path_conds[ai] = sym.add_pred(op_byte, lhs, rhs);
        }
        let n = sym.path_conds.len();
        // Vars referenced by the branch conds we will keep (pc >= anchor).
        // The kernel re-materializes a kept branch's operand bound preds at
        // the suffix base via bcf_reg_expr's lazy bcf_bound_reg, even when the
        // bound pred was originally emitted before the anchor (e.g. a port
        // field masked to <=0xffff at pc<anchor but compared in the proto
        // body after it). Re-add those bound preds so the goal matches the
        // kernel's re-materialized operand set.
        let mut kept_branch_vars: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for i in 0..n {
            if sym.path_cond_is_branch[i] && sym.path_cond_pcs[i] >= anchor_pc {
                for v in sym.collect_vars(sym.path_conds[i]) {
                    kept_branch_vars.insert(v);
                }
            }
        }
        let mut kc = Vec::with_capacity(n);
        let mut kp = Vec::with_capacity(n);
        let mut kb = Vec::with_capacity(n);
        let mut kn = Vec::with_capacity(n);
        let mut km = Vec::with_capacity(n);
        for i in 0..n {
            let pc = sym.path_cond_pcs[i];
            let is_branch = sym.path_cond_is_branch[i];
            let keep = pc == 0
                || pc >= anchor_pc
                // Bound pred (is_branch=false) for a var a kept branch uses.
                || (!is_branch && !kept_branch_vars.is_empty() && {
                    let vs = sym.collect_vars(sym.path_conds[i]);
                    !vs.is_empty() && vs.is_subset(&kept_branch_vars)
                });
            if keep {
                kc.push(sym.path_conds[i]);
                kp.push(pc);
                kb.push(is_branch);
                kn.push(sym.path_cond_narrowed_const[i]);
                km.push(sym.path_cond_lhs_meta[i]);
            }
        }
        if kc.is_empty() || kc.len() == n {
            return None; // filter changed nothing → no distinct variant
        }
        if std::env::var("ZOVIA_DUMP_DISCHARGE").ok().as_deref() == Some("1") {
            eprintln!(
                "[flag-skip-base] exit={} anchor_pc={} conds {}->{}",
                exit,
                anchor_pc,
                n,
                kc.len()
            );
        }
        sym.path_conds = kc;
        sym.path_cond_pcs = kp;
        sym.path_cond_is_branch = kb;
        sym.path_cond_narrowed_const = kn;
        sym.path_cond_lhs_meta = km;
    }

    // Loop-entry-base discharge variant (accepted_entrypoint proto-switch
    // `u>=`-anchored family — the OTHER engine-shape half). Some routes reach
    // the proto-switch reject via the ZERO-iteration loop route: the loop
    // bound check `If R8 u>= R1` is true on the first eval (R8=0), so the loop
    // body never runs and no back-edge cond is recorded. The kernel anchors
    // bcf_track at that loop-header bound check — its obligation has the bound
    // check (`0 u>= 0` if R1 const, or `0 u>= zext(R1)` if symbolic) + the
    // proto suffix, and NO loop-iteration conds. zovia records the same bound
    // check (lhs already const 0) but its base_pc discharges anchor pre-loop
    // (including extra prefix) and its FAITHFUL_FOLD over-collapses the
    // symbolic `0 u>= zext(R1)` to the trivially-true `1 != 0`. Re-anchor at
    // the loop-header pc WITHOUT folding (keep the recorded bound check),
    // dropping the pre-header prefix. ADDITIVE + deduped. None when the header
    // pc isn't a recorded branch or the filter is a no-op.
    if let Some(anchor_pc) = loop_entry_anchor {
        // The header branch must be present as a recorded branch cond.
        let anchor_idx = (0..sym.path_cond_pcs.len())
            .find(|&i| sym.path_cond_is_branch[i] && sym.path_cond_pcs[i] == anchor_pc)?;
        // Optionally fold the anchor bound-check `Klhs op X` to the literal
        // `Klhs op Klhs` (the kernel's const-bound `0 u>= 0` form). Read the
        // recorded pred's op + LHS const + width from the expr table; emit
        // `add_val(lhs_k) op add_val(lhs_k)`. Done BEFORE kept_branch_vars so
        // the now-orphaned RHS reg VAR's bound preds drop out. cvc5 validates:
        // on a symbolic-bound route this removes the X-constraint → not unsat →
        // dropped, so it only adds the genuine const-bound obligation.
        if loop_entry_fold {
            // slot -> expr index
            let mut slot_to_idx: std::collections::HashMap<u32, usize> =
                std::collections::HashMap::new();
            {
                let mut sl: u32 = 0;
                for (i, e) in sym.exprs.iter().enumerate() {
                    slot_to_idx.insert(sl, i);
                    sl += e.slot_len();
                }
            }
            let read_const = |slot: u32| -> Option<u64> {
                let e = sym.exprs.get(*slot_to_idx.get(&slot)?)?;
                // CONST: code & 0xf8 == 0x08
                if e.code & 0xf8 == 0x08 {
                    let lo = *e.args.first()? as u64;
                    let hi = e.args.get(1).copied().unwrap_or(0) as u64;
                    Some(if e.args.len() >= 2 {
                        lo | (hi << 32)
                    } else {
                        lo
                    })
                } else {
                    None
                }
            };
            let acond = sym.path_conds[anchor_idx];
            let folded = slot_to_idx.get(&acond).and_then(|&ei| {
                let e = &sym.exprs[ei];
                if e.args.len() != 2 {
                    return None;
                }
                let op = e.code & 0xfe; // strip BCF_BV
                let jmp32 = e.params == 32;
                let lhs_k = read_const(e.args[0])?;
                Some((op, lhs_k, jmp32))
            });
            match folded {
                Some((op, lhs_k, jmp32)) => {
                    let l = sym.add_val(lhs_k, jmp32);
                    let r = sym.add_val(lhs_k, jmp32);
                    sym.path_conds[anchor_idx] = sym.add_pred(op, l, r);
                }
                None => return None, // LHS not a const → can't form K op K
            }
        }
        let n = sym.path_conds.len();
        let mut kept_branch_vars: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for i in 0..n {
            if sym.path_cond_is_branch[i] && sym.path_cond_pcs[i] >= anchor_pc {
                for v in sym.collect_vars(sym.path_conds[i]) {
                    kept_branch_vars.insert(v);
                }
            }
        }
        let mut kc = Vec::with_capacity(n);
        let mut kp = Vec::with_capacity(n);
        let mut kb = Vec::with_capacity(n);
        let mut kn = Vec::with_capacity(n);
        let mut km = Vec::with_capacity(n);
        for i in 0..n {
            let pc = sym.path_cond_pcs[i];
            let is_branch = sym.path_cond_is_branch[i];
            let keep = pc == 0
                || pc >= anchor_pc
                || (!is_branch && !kept_branch_vars.is_empty() && {
                    let vs = sym.collect_vars(sym.path_conds[i]);
                    !vs.is_empty() && vs.is_subset(&kept_branch_vars)
                });
            if keep {
                kc.push(sym.path_conds[i]);
                kp.push(pc);
                kb.push(is_branch);
                kn.push(sym.path_cond_narrowed_const[i]);
                km.push(sym.path_cond_lhs_meta[i]);
            }
        }
        if kc.is_empty() || kc.len() == n {
            return None;
        }
        if std::env::var("ZOVIA_DUMP_DISCHARGE").ok().as_deref() == Some("1") {
            eprintln!(
                "[loop-entry-base] anchor_pc={} conds {}->{}",
                anchor_pc,
                n,
                kc.len()
            );
        }
        sym.path_conds = kc;
        sym.path_cond_pcs = kp;
        sym.path_cond_is_branch = kb;
        sym.path_cond_narrowed_const = kn;
        sym.path_cond_lhs_meta = km;
    }

    // Build the goal root: for path-unreachable the goal is the path_cond
    // CONJ itself (no extra refine_cond). Mirrors kernel `bcf_track`'s
    // construction at verifier.c:24380-24384 (the same path_cond expr the
    // kernel passes to bcf_bundle_try_discharge via the -1 fallback).
    let goal_root = match sym.path_conds.len() {
        0 => return None,
        1 => sym.path_conds[0],
        _ => {
            let pcs = sym.path_conds.clone();
            sym.add_conj(pcs)
        }
    };

    // Don't set sym.refine_cond — leaving it None makes smtlib::encode
    // emit `(assert <path_conds>)` directly (no nested CONJ with a
    // refine_cond), which is what we want for the path-unreachable proof.

    let smt = match smtlib::encode(&sym) {
        Ok(s) => s,
        Err(e) => {
            warn!("[bcf] path-unreachable: SMT-LIB encode failed: {}", e);
            return None;
        }
    };
    if std::env::var("ZOVIA_BCF_DUMP_SMT").is_ok() {
        eprintln!(
            "---- [bcf] SMT-LIB to cvc5 (path-unreachable) ----\n{}\n---- end ----",
            smt
        );
    }

    match solver::solve(&smt) {
        Ok(bytes) => {
            debug!(
                "[bcf] path-unreachable: cvc5 accepted ({} bytes)",
                bytes.len()
            );
            Some(UnreachableOk {
                proof_bytes: bytes,
                goal_root,
                sym,
            })
        }
        Err(e) => {
            debug!("[bcf] path-unreachable: cvc5 declined ({})", e);
            // Kernel-mirror rewrite (K==K) above may have removed a
            // constraint that was load-bearing for unsat. Fallback: undo
            // the rewrite and retry with the original VAR-form path_conds.
            // Loses byte-match with kernel for this entry but preserves
            // discharge for cases where the K==K rewrite weakens the
            // formula (e.g. when other conjuncts don't independently pin
            // the LHS via spill/fill propagation).
            if sym.path_conds != original_path_conds {
                sym.path_conds = original_path_conds;
                let fallback_goal = match sym.path_conds.len() {
                    0 => return None,
                    1 => sym.path_conds[0],
                    _ => {
                        let pcs = sym.path_conds.clone();
                        sym.add_conj(pcs)
                    }
                };
                let smt2 = match smtlib::encode(&sym) {
                    Ok(s) => s,
                    Err(_) => return None,
                };
                if let Ok(bytes) = solver::solve(&smt2) {
                    debug!(
                        "[bcf] path-unreachable: cvc5 accepted fallback ({} bytes)",
                        bytes.len()
                    );
                    return Some(UnreachableOk {
                        proof_bytes: bytes,
                        goal_root: fallback_goal,
                        sym,
                    });
                }
            }
            None
        }
    }
}

/// Build a path-unreachable proof directly from a SymbolicState whose
/// `path_conds` were produced by the faithful base→reject replay.
/// Unlike [`try_prove_unreachable_inner`], this does
/// NO suffix filter and NO K==K / fresh-VAR fold rewrites — the replay
/// already re-materialized every register exactly as the kernel's
/// `bcf_track` re-execution does (verifier.c:24633 + bcf_reg_expr@897), so
/// `path_conds` is the kernel-faithful goal verbatim. Just CONJ + cvc5.
pub fn build_unreachable_from_replay(mut sym: SymbolicState) -> Option<UnreachableOk> {
    if sym.path_conds.is_empty() {
        return None;
    }
    let goal_root = match sym.path_conds.len() {
        0 => return None,
        1 => sym.path_conds[0],
        _ => {
            let pcs = sym.path_conds.clone();
            sym.add_conj(pcs)
        }
    };
    let smt = smtlib::encode(&sym).ok()?;
    if std::env::var("ZOVIA_BCF_DUMP_SMT").is_ok() {
        eprintln!(
            "---- [bcf] SMT-LIB to cvc5 (replay) ----\n{}\n---- end ----",
            smt
        );
    }
    // Formation-time census (diagnosis): the post-prove [census] lines can't
    // distinguish never-formed from formed-but-prove-declined; log both the
    // formed hash and the solve outcome.
    let census = std::env::var("ZOVIA_BCF_CENSUS").ok().as_deref() == Some("1");
    let formed_hash = if census {
        Some(super::canonical_hash::hash_expr(goal_root, &sym.exprs))
    } else {
        None
    };
    let solved = solver::solve(&smt);
    if let Some(h) = formed_hash {
        eprintln!(
            "[census-formed] hash={:016x} solve_ok={}",
            h,
            solved.is_ok()
        );
    }
    let bytes = solved.ok()?;
    Some(UnreachableOk {
        proof_bytes: bytes,
        goal_root,
        sym,
    })
}
