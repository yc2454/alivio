//! Refinement callback for the map-region OOB rejection sites.
//!
//! Mirrors the kernel's `__bcf_refine_access_bound` (verifier.c:5291) for
//! the map / helper-mem-region case. Three sub-cases dispatched on which
//! operand carries the variable part:
//!
//! * **(i) `ptr_const`** — pointer has no variable contribution; size is
//!   variable. Refine the size's upper bound by claiming
//!   `JGT(size_expr, higher_bound - off)` is unsat.
//!
//! * **(ii) `size_const`** — size is a known constant; pointer offset is
//!   variable. Refine the offset's range by claiming
//!   `JSGT(off_expr, higher_bound - sz - off)` is unsat, optionally
//!   disjoined with `JSLT(off_expr, lower_bound - off)` when the verifier
//!   can't already prove the low side.
//!
//! * **(iii) `both_var`** — both vary. Build `ADD(off_expr, size_expr)`
//!   then `JSGT(sum, higher_bound - off)`; optional low-side DISJ as above.
//!
//! All predicates use bit-width 32 when **both** `ptr_reg` and `size_reg`
//! fit in s32 (kernel verifier.c:5306-5310), and 64 otherwise. The
//! constant K (= `ptr_reg->off`, the accumulated pointer const offset
//! after `ptr += imm` ops) comes from `state.ptr_const_off`, as in
//! refine_stack, so multi-variable-contributor chains stay exact.
//!
//! This shape is critical for `bcf_bundle_try_discharge`: the kernel
//! computes `canonical_hash` on its runtime CONJ and looks the bundle up
//! by that hash. Any structural divergence (operand width, conditional-
//! DISJ vs unconditional, extra path_conds beyond what the kernel
//! generates) → hash miss → -EACCES at the refine site.

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::analysis::transfer::alu::helpers::bcf_reg_bounds;
use crate::refinement::bcf::{BPF_ADD, BPF_JGT, BPF_JSGT, BPF_JSLT};
use crate::refinement::smtlib;
use crate::refinement::solver;
use crate::refinement::symbolic::{build_goal_root, SymbolicState};
use log::{debug, warn};

pub fn try_refine_map_access(
    state: &State,
    base: Reg,
    insn_off: i64,
    size: i64,
    map_limit: i64,
    size_reg: Option<Reg>,
    base_pc: Option<usize>,
    base_conds_len: Option<usize>,
    // Pre-solve dedupe (replay-ladder cost control): when set, the built
    // goal's canonical hash is computed BEFORE the cvc5 solve and the
    // attempt bails if the hash is already known (it would be dropped at
    // push time anyway — replay variants dedupe by cond_hash). Purely an
    // optimization: bundle output is identical with or without it.
    skip_hashes: Option<&std::collections::HashSet<u64>>,
) -> Option<super::refine_stack::RefineOk> {
    let bcf_ref = state.bcf.as_ref()?;
    let mut sym: SymbolicState = (**bcf_ref).clone();
    // Mirror the kernel's `bcf_track` suffix-only br_cond emission
    // (verifier.c `bcf_track` / `backtrack_states`). Drop path_conds
    // emitted at PCs before the refine target's definition chain
    // bottoms out so the bundle's canonical_hash matches what the
    // kernel computes on its runtime CONJ.
    let pre_count = sym.path_conds.len();
    // Kernel bcf_track slices the cond stream POSITIONALLY (the suffix
    // of the walk from the base state to cur), not by pc value; the two
    // coincide on straight-line paths, but when the path wraps a loop
    // the pc filter over-keeps earlier-iteration conds. `base_conds_len`
    // = the base state's own path_conds length (its snapshot is a prefix
    // of cur's stream — same lineage) = the exact positional cut. The
    // positional path engages only when it disagrees with the legacy pc
    // filter, and then also runs the kernel replay-fold
    // (faithful_fold_pass — bcf_refine tail resets bcf_expr, so
    // pre-base operand chains rematerialize as fresh VARs + bound
    // preds; verifier.c:894-926 lazy bcf_reg_expr).
    // DEFAULT OFF: a coherent goal also needs the refine predicate
    // rebuilt over the same fresh expr table (kernel bcf_track = ONE
    // replay table; zovia's refine pred is built from the live reg
    // chains, so the fold pass's fresh vars orphan it → cvc5 SAT → no
    // goal). Enabling requires replay-rebuild integration for refine
    // goals.
    let positional_enabled =
        std::env::var("ZOVIA_BCF_REFINE_POSITIONAL_CUT").ok().as_deref() == Some("1");
    let mut positional_engaged = false;
    if let (true, Some(bp), Some(cut)) = (positional_enabled, base_pc, base_conds_len) {
        if cut <= sym.path_conds.len() {
            let legacy_kept: Vec<usize> = sym
                .path_cond_pcs
                .iter()
                .enumerate()
                .filter(|&(_, &pc)| pc == 0 || pc >= bp)
                .map(|(i, _)| i)
                .collect();
            let positional_kept: Vec<usize> = sym
                .path_cond_pcs
                .iter()
                .enumerate()
                .filter(|&(i, &pc)| pc == 0 || i >= cut)
                .map(|(i, _)| i)
                .collect();
            if legacy_kept != positional_kept {
                sym.retain_path_conds_by_index(&positional_kept);
                super::refine_unreachable::faithful_fold_pass(&mut sym, base_pc);
                positional_engaged = true;
            }
        }
    }
    if let Some(bp) = base_pc {
        if !positional_engaged {
            // TODO(faithful): plumb prev_insn_pc from caller (mirror of
            // refine_unreachable's wiring) so the kernel's record_path_cond
            // at replay-start is also captured for map-bounds refinement.
            sym.filter_path_conds_from_pc(bp, None);
        }
    }
    if std::env::var("ZOVIA_BCF_TRACK_DEBUG").is_ok() {
        eprintln!(
            "[bcf-track] map-refine base={:?} size_reg={:?} base_pc={:?} path_conds {}->{} pcs={:?}",
            base,
            size_reg,
            base_pc,
            pre_count,
            sym.path_conds.len(),
            sym.path_cond_pcs,
        );
    }

    // Pointer's variable-part expression. After the ptr+imm BCF skip, the
    // cached `bcf_expr` carries only the symbolic variable contribution;
    // the constant K lives separately in `state.ptr_const_off`.
    let b_idx = base.bcf_idx()?;
    let var_off_expr = sym.get_reg(b_idx);

    // Kernel `ptr_reg->off` analog. Combined with the load/store
    // instruction's static `insn_off`, this gives the total const offset
    // the refine_cond threshold subtracts from `higher_bound`.
    let const_off = state.ptr_const_off.get(&base).copied().unwrap_or(0);
    let total_off = const_off + insn_off;

    let higher_bound: i64 = map_limit;
    let lower_bound: i64 = 0;

    // Decide case classification (mirrors kernel's `tnum_is_const` checks
    // at verifier.c:5315, 5328). `ptr_is_var` iff the pointer has any
    // variable contributor; `size_is_var` iff the size register isn't a
    // statically-pinned constant.
    let ptr_is_var = var_off_expr.is_some()
        && state.var_off_contributor.get(&base).is_some();
    let (size_const_val, size_expr_cached) = match size_reg {
        Some(sz_reg) => {
            let c = state.domain.get_fixed_value(sz_reg);
            let cached = sz_reg.bcf_idx().and_then(|si| sym.get_reg(si));
            (c, cached)
        }
        None => (Some(size), None),
    };
    let size_is_var = size_const_val.is_none();

    // Width discipline: kernel uses 32-bit ops when both regs fit_s32
    // (verifier.c:5306-5310). For zovia, default to fit_s32 of ptr alone
    // when there's no size_reg.
    let ptr_bounds = bcf_reg_bounds(state, base);
    let bit32 = if let Some(sz_reg) = size_reg {
        let size_bounds = bcf_reg_bounds(state, sz_reg);
        ptr_bounds.fit_s32() && size_bounds.fit_s32()
    } else {
        ptr_bounds.fit_s32()
    };
    let bitsz: u16 = if bit32 { 32 } else { 64 };

    // Compute min_off for the conditional-DISJ check (kernel verifier.c:
    // 5339, 5360). zovia tracks the pointer's signed lower bound directly.
    let (smin, _smax) = state.domain.get_interval(base);
    let min_off = smin.saturating_add(insn_off);

    // Helper to peel the cached 64-bit expression to its 32-bit form when
    // bit32, matching kernel `bcf_expr32`.
    let peel = |sym: &mut SymbolicState, idx: u32| -> u32 {
        if bit32 {
            sym.expr32(idx)
        } else {
            idx
        }
    };

    if std::env::var("ZOVIA_TRACE_REFINE_CASE").ok().as_deref() == Some("1") {
        eprintln!(
            "[REFINE-CASE] ptr_is_var={} size_is_var={} size_expr_cached={:?} var_off_expr={:?} ptr_const_off={} insn_off={} total_off={} size_const={:?} bit32={}",
            ptr_is_var, size_is_var, size_expr_cached, var_off_expr, const_off, insn_off, total_off, size_const_val, bit32,
        );
    }
    let oob = if !ptr_is_var && size_is_var {
        // Case (i): ptr const, refine size. Kernel verifier.c:5315-5326.
        // refine_cond = JGT(size_expr, higher_bound - off)   (UNSIGNED JGT)
        let size_expr = size_expr_cached?;
        let size_use = peel(&mut sym, size_expr);
        let thresh = higher_bound.wrapping_sub(total_off);
        let thresh_expr = sym.add_val(thresh as u64, bit32);
        sym.add_pred(BPF_JGT, size_use, thresh_expr)
    } else if ptr_is_var && !size_is_var {
        // Case (ii): size const, refine ptr off. Kernel verifier.c:5328-5345.
        // high_pred = JSGT(off_expr, higher_bound - sz - off)
        // optional DISJ with JSLT(off_expr, lower_bound - off)
        let off_idx = var_off_expr?;
        let off_use = peel(&mut sym, off_idx);
        let sz = size_const_val.unwrap();
        let high_thresh = higher_bound.wrapping_sub(sz).wrapping_sub(total_off);
        let high_thresh_expr = sym.add_val(high_thresh as u64, bit32);
        let high_pred = sym.add_pred(BPF_JSGT, off_use, high_thresh_expr);
        if min_off < lower_bound {
            let low_thresh = lower_bound.wrapping_sub(total_off);
            let low_thresh_expr = sym.add_val(low_thresh as u64, bit32);
            let low_pred = sym.add_pred(BPF_JSLT, off_use, low_thresh_expr);
            sym.add_disj(vec![low_pred, high_pred])
        } else {
            high_pred
        }
    } else if ptr_is_var && size_is_var {
        // Case (iii): both var. Kernel verifier.c:5352-5388.
        // high_pred = JSGT(ADD(off_expr, size_expr), higher_bound - off)
        // optional DISJ with JSLT(off_expr, lower_bound - off)
        let off_idx = var_off_expr?;
        let size_expr = size_expr_cached?;
        let off_use = peel(&mut sym, off_idx);
        let size_use = peel(&mut sym, size_expr);
        let sum_expr = sym.add_alu(BPF_ADD, off_use, size_use, bitsz);
        let high_thresh = higher_bound.wrapping_sub(total_off);
        let high_thresh_expr = sym.add_val(high_thresh as u64, bit32);
        let high_pred = sym.add_pred(BPF_JSGT, sum_expr, high_thresh_expr);
        if min_off < lower_bound {
            let low_thresh = lower_bound.wrapping_sub(total_off);
            let low_thresh_expr = sym.add_val(low_thresh as u64, bit32);
            let low_pred = sym.add_pred(BPF_JSLT, off_use, low_thresh_expr);
            sym.add_disj(vec![low_pred, high_pred])
        } else {
            high_pred
        }
    } else {
        // Both const: there's nothing to refine — the verifier should have
        // proven the bounds itself. Bail.
        debug!("[bcf] map-refine skipped: both ptr and size are const");
        return None;
    };

    sym.set_refine_cond(oob);

    let smt = match smtlib::encode(&sym) {
        Ok(s) => s,
        Err(e) => {
            if std::env::var("ZOVIA_TRACE_REFINE_CASE").ok().as_deref() == Some("1") {
                eprintln!("[REFINE-CASE] SMT encode FAILED: {}", e);
            }
            warn!("[bcf] map SMT-LIB encode failed: {}", e);
            return None;
        }
    };
    if std::env::var("ZOVIA_BCF_DUMP_SMT").is_ok() {
        eprintln!("---- [bcf] SMT-LIB to cvc5 (map) ----\n{}\n---- end ----", smt);
    }
    // Goal root built before the solve so the canonical hash is available
    // for the pre-solve dedupe; `sym` is local, ordering is inert.
    let goal_root = build_goal_root(&mut sym, oob);
    // Kernel checker cap: bcf_check_proof's var-equivalence map holds at
    // most BCF_MAX_VAR_MAP = 128 variables (bcf_checker.c:1115); an entry
    // whose goal exceeds it FAILS bcf_bundle_prevalidate and the kernel
    // rejects the WHOLE bundle with -EINVAL before any verification.
    // Anything past the cap is dead weight that bricks the bundle —
    // drop it before wasting a solve.
    {
        use crate::refinement::bcf::{BCF_OP_MASK, BCF_VAR};
        let nvars = sym
            .exprs
            .iter()
            .filter(|e| (e.code & BCF_OP_MASK) == BCF_VAR)
            .count();
        if nvars > 128 {
            return None;
        }
    }
    if let Some(skip) = skip_hashes
        && skip.contains(&crate::refinement::canonical_hash::hash_expr(goal_root, &sym.exprs))
    {
        return None;
    }
    match solver::solve(&smt) {
        Ok(bytes) => {
            debug!(
                "[bcf] map-OOB refinement: cvc5 accepted ({} bytes)",
                bytes.len()
            );
            Some(super::refine_stack::RefineOk { proof_bytes: bytes, goal_root, sym })
        }
        Err(e) => {
            if std::env::var("ZOVIA_TRACE_REFINE_CASE").ok().as_deref() == Some("1") {
                eprintln!("[REFINE-CASE] cvc5 DECLINED: {}", e);
            }
            debug!("[bcf] map-OOB refinement: cvc5 declined ({})", e);
            None
        }
    }
}
