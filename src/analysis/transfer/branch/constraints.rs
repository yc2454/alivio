// src/analysis/transfer/branch/constraints.rs

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use crate::ast::{CmpOp, Width};
use crate::domains::numeric::NumericDomain;
use crate::domains::tnum::Tnum;
use either::Either::{self};

use super::outcome::{fits_in_i32, fits_in_u32, get_combined_signed_bounds};

/// Propagate a constraint to all registers with the same scalar_id as source_reg.
/// This is used in the interval domain to track bounds across register copies.
fn interval_propagate_scalars<F>(domain: &mut NumericDomain, source_reg: Reg, apply: F)
where
    F: Fn(&mut NumericDomain, Reg),
{
    if let NumericDomain::Interval(ivl) = domain {
        let source_id = ivl.get(source_reg).bounds.scalar_id;
        if let Some(id) = source_id {
            // Collect registers with matching scalar_id
            let matching_regs: Vec<Reg> = Reg::ALL
                .iter()
                .copied()
                .filter(|&r| {
                    r != source_reg
                        && r != Reg::Zero
                        && !r.is_anchor()
                        && ivl.get(r).bounds.scalar_id == Some(id)
                })
                .collect();
            // Apply constraint to each matching register
            for r in matching_regs {
                apply(domain, r);
            }
        }
    }
}

pub fn apply_jmp_constraints(
    then_s: &mut State,
    else_s: &mut State,
    left: Reg,
    op: CmpOp,
    width: Width,
    right: Either<Reg, i64>,
) {
    if op == CmpOp::Test {
        apply_test_constraints(then_s, else_s, left, width, right);
        return;
    }

    // Kernel `reg_set_min_max` (verifier.c v6.15 L16082) returns early
    // without refining numeric bounds when either operand is a pointer.
    // Narrowly mirror that for the PtrToCtx-vs-Imm case: ctx is a
    // non-nullable, non-arithmetic pointer with no useful numeric value
    // to refine. zovia's unconditional refinement was the missing piece
    // behind the conditional_loop FA (verifier_cfg.c): visit-2 of the
    // loop head had r1=PtrToCtx refined to [0,0] (taken edge of
    // `r1 == 0`) while cached visit-1 kept r1 unrefined, so the
    // inf-loop trap missed the recurrence. Suppressing the refinement
    // here keeps both visits' r1 byte-identical and lets the trap fire.
    //
    // Scoped narrowly to PtrToCtx-vs-Imm rather than all pointer-vs-Imm:
    // null-checks on PtrToMapValueOrNull / acquired-ref kinds have
    // downstream type-promotion (refine_branch) intertwined with the
    // numeric refinement, so a broader guard would lose precision.
    // PtrToCtx is unique in being
    // non-nullable with no map-value-style type transition, so
    // suppressing its refinement has no downstream consumer.
    if matches!(right, Either::Right(_)) && matches!(then_s.types.get(left), RegType::PtrToCtx) {
        return;
    }

    let (resolved, right_bounds) = resolve_right_operand(&then_s.domain, right, width, op);
    if can_apply_dbm_constraint(then_s, left, op, width, right_bounds, resolved) {
        apply_cmp_to_domain(&mut then_s.domain, &mut else_s.domain, left, op, resolved);
    } else if width == Width::W64 && matches!(op, CmpOp::UGt | CmpOp::UGe | CmpOp::ULt | CmpOp::ULe)
    {
        apply_unsigned_const_fallback(then_s, else_s, left, op, resolved);
    } else if width == Width::W32 && matches!(op, CmpOp::SLt | CmpOp::SLe | CmpOp::SGt | CmpOp::SGe)
    {
        apply_w32_signed_fallback(then_s, else_s, left, op, resolved);
    } else if width == Width::W32
        && matches!(
            op,
            CmpOp::ULt | CmpOp::ULe | CmpOp::UGt | CmpOp::UGe | CmpOp::Eq | CmpOp::Ne
        )
    {
        apply_w32_unsigned_fallback(then_s, else_s, left, op, resolved);
    }

    let imm_val = match resolved {
        Either::Right(v) => Some(v),
        Either::Left(_) => None,
    };
    apply_eq_refinements(then_s, else_s, left, op, width, imm_val);
}

fn can_apply_dbm_constraint(
    state: &State,
    left: Reg,
    op: CmpOp,
    width: Width,
    right_bounds: (i64, i64),
    right: Either<Reg, i64>,
) -> bool {
    // For interval domain, skip scalar constraint propagation for packet pointer
    // comparisons. The relationship between pkt_data/pkt_end is tracked via
    // packet_size_lower_bound, not scalar bounds. Applying scalar constraints
    // to packet pointers with unknown absolute values incorrectly marks
    // branches as infeasible.
    if matches!(state.domain, NumericDomain::Interval(_)) {
        if !interval_can_apply_constraint(state, left, right) {
            return false;
        }
    }

    let dominated_by_signed = matches!(op, CmpOp::SLt | CmpOp::SLe | CmpOp::SGt | CmpOp::SGe);
    let dominated_by_unsigned = matches!(op, CmpOp::ULt | CmpOp::ULe | CmpOp::UGt | CmpOp::UGe);

    if width == Width::W32 {
        // W32 Eq/Ne against an IMMEDIATE narrow only the LOW 32 bits (the
        // subreg). The full-reg `assume_eq_imm` in apply_cmp_to_domain
        // would zero the whole 64-bit reg (e.g. `w0 == 0` ⇒ R0 == 0),
        // losing the high-32 bits the kernel keeps unknown. Route these to
        // apply_w32_unsigned_fallback, which narrows u32 bounds +
        // refine_subreg_tnum (upper 32 preserved), so reg_bounds_sync's
        // 32→64 mixed deduction yields the kernel's umax/smax.
        // Restricted to imm operands: the fallback can't narrow a
        // reg==reg compare (no const), and diverting those would drop
        // apply_cmp_to_domain's intersect_eq_reg.
        if matches!(op, CmpOp::Eq | CmpOp::Ne) && matches!(right, Either::Right(_)) {
            return false;
        }
        let left_bounds = get_combined_signed_bounds(state, left);
        if dominated_by_signed {
            return fits_in_i32(left_bounds) && fits_in_i32(right_bounds);
        } else if dominated_by_unsigned {
            return fits_in_u32(left_bounds) && fits_in_u32(right_bounds);
        }
    }

    if dominated_by_unsigned {
        let left_bounds = get_combined_signed_bounds(state, left);
        let left_nonneg = left_bounds.0 >= 0;
        let left_unbounded = {
            let (lo, _) = state.domain.get_interval(left);
            let tnum = state.get_tnum(left);
            lo == i64::MIN && tnum.max_value() > i64::MAX as u64
        };
        let right_nonneg = right_bounds.0 >= 0;
        let right_is_pointer = match right {
            Either::Left(reg) => state.types.get(reg).is_pointer(),
            _ => false,
        };
        return (left_nonneg || left_unbounded) && (right_nonneg || right_is_pointer);
    }

    true
}

fn apply_cmp_to_domain(
    then_domain: &mut NumericDomain,
    else_domain: &mut NumericDomain,
    left: Reg,
    op: CmpOp,
    right: Either<Reg, i64>,
) {
    match (op, right) {
        (CmpOp::Eq, Either::Right(imm)) => {
            then_domain.assume_eq_imm(left, imm);
            interval_propagate_scalars(then_domain, left, |d, r| d.assume_eq_imm(r, imm));
            // else: left != imm — tighten if imm matches a boundary.
            refine_ne_imm(else_domain, left, imm);
        }
        (CmpOp::Eq, Either::Left(reg)) => {
            then_domain.intersect_eq_reg(left, reg);
        }
        (CmpOp::Ne, Either::Right(imm)) => {
            else_domain.assume_eq_imm(left, imm);
            interval_propagate_scalars(else_domain, left, |d, r| d.assume_eq_imm(r, imm));
            // then: left != imm — tighten if imm matches a boundary.
            // Closes verifier_bounds::reg_{equal,not_equal}_const where
            // `r4 &= 7; if r4 != 0 goto l0` should refine r4 to [1, 7]
            // on the L0 path so `bpf_skb_store_bytes(..., r4)` (which
            // requires `ARG_CONST_SIZE > 0`) accepts.
            refine_ne_imm(then_domain, left, imm);
        }
        (CmpOp::Ne, Either::Left(reg)) => {
            else_domain.intersect_eq_reg(left, reg);
        }
        (CmpOp::UGe, Either::Right(imm)) => {
            then_domain.assume_ge_imm(left, imm);
            interval_propagate_scalars(then_domain, left, |d, r| d.assume_ge_imm(r, imm));
            else_domain.assume_lt_imm(left, imm);
            interval_propagate_scalars(else_domain, left, |d, r| d.assume_lt_imm(r, imm));
            if imm > 0 {
                else_domain.assume_ge_imm(left, 0);
                interval_propagate_scalars(else_domain, left, |d, r| d.assume_ge_imm(r, 0));
            }
        }
        (CmpOp::SGe, Either::Right(imm)) => {
            then_domain.assume_ge_imm(left, imm);
            interval_propagate_scalars(then_domain, left, |d, r| d.assume_ge_imm(r, imm));
            else_domain.assume_lt_imm(left, imm);
            interval_propagate_scalars(else_domain, left, |d, r| d.assume_lt_imm(r, imm));
        }
        (CmpOp::UGe, Either::Left(reg)) => {
            then_domain.assume_ge(left, reg);
            else_domain.assume_le_offset(left, reg, -1);
            else_domain.assume_ge_imm(left, 0);
            interval_propagate_scalars(else_domain, left, |d, r| d.assume_ge_imm(r, 0));
        }
        (CmpOp::SGe, Either::Left(reg)) => {
            then_domain.assume_ge(left, reg);
            else_domain.assume_le_offset(left, reg, -1);
        }
        (CmpOp::UGt, Either::Right(imm)) => {
            then_domain.assume_ge_imm(left, imm + 1);
            interval_propagate_scalars(then_domain, left, |d, r| d.assume_ge_imm(r, imm + 1));
            else_domain.assume_le_imm(left, imm);
            interval_propagate_scalars(else_domain, left, |d, r| d.assume_le_imm(r, imm));
            else_domain.assume_ge_imm(left, 0);
            interval_propagate_scalars(else_domain, left, |d, r| d.assume_ge_imm(r, 0));
        }
        (CmpOp::SGt, Either::Right(imm)) => {
            then_domain.assume_ge_imm(left, imm + 1);
            interval_propagate_scalars(then_domain, left, |d, r| d.assume_ge_imm(r, imm + 1));
            else_domain.assume_le_imm(left, imm);
            interval_propagate_scalars(else_domain, left, |d, r| d.assume_le_imm(r, imm));
        }
        (CmpOp::UGt, Either::Left(reg)) => {
            then_domain.assume_gt(left, reg);
            else_domain.assume_le(left, reg);
            else_domain.assume_ge_imm(left, 0);
            interval_propagate_scalars(else_domain, left, |d, r| d.assume_ge_imm(r, 0));
        }
        (CmpOp::SGt, Either::Left(reg)) => {
            then_domain.assume_gt(left, reg);
            else_domain.assume_le(left, reg);
        }
        (CmpOp::ULe, Either::Right(imm)) => {
            then_domain.assume_le_imm(left, imm);
            interval_propagate_scalars(then_domain, left, |d, r| d.assume_le_imm(r, imm));
            then_domain.assume_ge_imm(left, 0);
            interval_propagate_scalars(then_domain, left, |d, r| d.assume_ge_imm(r, 0));
            else_domain.assume_ge_imm(left, imm + 1);
            interval_propagate_scalars(else_domain, left, |d, r| d.assume_ge_imm(r, imm + 1));
        }
        (CmpOp::SLe, Either::Right(imm)) => {
            then_domain.assume_le_imm(left, imm);
            interval_propagate_scalars(then_domain, left, |d, r| d.assume_le_imm(r, imm));
            else_domain.assume_ge_imm(left, imm + 1);
            interval_propagate_scalars(else_domain, left, |d, r| d.assume_ge_imm(r, imm + 1));
        }
        (CmpOp::ULe, Either::Left(reg)) => {
            then_domain.assume_le(left, reg);
            then_domain.assume_ge_imm(left, 0);
            interval_propagate_scalars(then_domain, left, |d, r| d.assume_ge_imm(r, 0));
            else_domain.assume_gt(left, reg);
        }
        (CmpOp::SLe, Either::Left(reg)) => {
            then_domain.assume_le(left, reg);
            else_domain.assume_gt(left, reg);
        }
        (CmpOp::ULt, Either::Right(imm)) => {
            then_domain.assume_lt_imm(left, imm);
            interval_propagate_scalars(then_domain, left, |d, r| d.assume_lt_imm(r, imm));
            if imm > 0 {
                then_domain.assume_ge_imm(left, 0);
                interval_propagate_scalars(then_domain, left, |d, r| d.assume_ge_imm(r, 0));
            }
            else_domain.assume_ge_imm(left, imm);
            interval_propagate_scalars(else_domain, left, |d, r| d.assume_ge_imm(r, imm));
        }
        (CmpOp::SLt, Either::Right(imm)) => {
            then_domain.assume_lt_imm(left, imm);
            interval_propagate_scalars(then_domain, left, |d, r| d.assume_lt_imm(r, imm));
            else_domain.assume_ge_imm(left, imm);
            interval_propagate_scalars(else_domain, left, |d, r| d.assume_ge_imm(r, imm));
        }
        (CmpOp::ULt, Either::Left(reg)) => {
            then_domain.assume_le_offset(left, reg, -1);
            then_domain.assume_ge_imm(left, 0);
            interval_propagate_scalars(then_domain, left, |d, r| d.assume_ge_imm(r, 0));
            else_domain.assume_ge(left, reg);
        }
        (CmpOp::SLt, Either::Left(reg)) => {
            then_domain.assume_le_offset(left, reg, -1);
            else_domain.assume_ge(left, reg);
        }
        (CmpOp::Test, _) => {}
    }
}

/// Refine `left != imm` against the domain's current interval.
/// If the constant matches the lower or upper bound, raise/lower the
/// boundary by one. Boundary-only refinement matches the kernel's
/// `tnum`-based shrink: a `!= imm` where `imm` is in the interior
/// can't tighten unsigned bounds.
fn refine_ne_imm(domain: &mut NumericDomain, left: Reg, imm: i64) {
    let (lo, hi) = domain.get_interval(left);
    if lo == imm && lo < hi {
        domain.assume_ge_imm(left, lo.saturating_add(1));
        interval_propagate_scalars(domain, left, |d, r| {
            d.assume_ge_imm(r, lo.saturating_add(1))
        });
    } else if hi == imm && lo < hi {
        domain.assume_le_imm(left, hi.saturating_sub(1));
        interval_propagate_scalars(domain, left, |d, r| {
            d.assume_le_imm(r, hi.saturating_sub(1))
        });
    }
    // Kernel regs_refine_cond_op BPF_JNE (!is_jmp32), verifier.c:17124:
    // the UNSIGNED edges are bumped independently of the signed pair —
    // for a full-range scalar (helper RET_INTEGER), `!= 0` gives
    // umin 0→1 while smin stays S64_MIN (the value may be a negative
    // errno). The signed interval above cannot carry this fact; without
    // it a later `if reg != 0` cannot fold one-sided and zovia walks a
    // contradictory arm the kernel never visits.
    let uval = imm as u64;
    let (umin, umax) = domain.get_u64_bounds(left);
    let new_umin = if umin == uval { umin.saturating_add(1) } else { umin };
    let new_umax = if umax == uval { umax.saturating_sub(1) } else { umax };
    if (new_umin, new_umax) != (umin, umax) && new_umin <= new_umax {
        domain.set_u64_bounds(left, new_umin, new_umax);
    }
}

fn apply_eq_refinements(
    then_s: &mut State,
    else_s: &mut State,
    left: Reg,
    op: CmpOp,
    width: Width,
    imm: Option<i64>,
) {
    // W32 Eq/Ne constrain only the LOW 32 bits — apply_w32_unsigned_fallback
    // already set the subreg tnum (upper 32 preserved) via
    // refine_subreg_tnum. Setting a full-width `Tnum::constant` here would
    // clobber the upper 32 bits back to known, re-introducing the
    // over-narrowing this routing was meant to avoid. So skip for W32.
    if width == Width::W32 {
        return;
    }
    match (op, imm) {
        (CmpOp::Eq, Some(v)) => {
            then_s.set_tnum(left, Tnum::constant(v as u64));
        }
        (CmpOp::Ne, Some(v)) => {
            else_s.set_tnum(left, Tnum::constant(v as u64));
        }
        _ => {}
    }
}

fn apply_test_constraints(
    then_s: &mut State,
    else_s: &mut State,
    left: Reg,
    width: Width,
    right: Either<Reg, i64>,
) {
    let mask = match right {
        Either::Right(imm) => {
            if width == Width::W32 {
                (imm as u32) as u64
            } else {
                imm as u64
            }
        }
        Either::Left(reg) => {
            if let Some(val) = then_s.domain.get_fixed_value(reg) {
                if width == Width::W32 {
                    (val as u32) as u64
                } else {
                    val as u64
                }
            } else {
                return;
            }
        }
    };

    let else_tnum = else_s.get_tnum(left);
    let refined = Tnum {
        value: else_tnum.value & !mask,
        mask: else_tnum.mask & !mask,
    };
    else_s.set_tnum(left, refined);

    if mask.is_power_of_two() {
        let bit_pos = mask.trailing_zeros();
        let then_tnum = then_s.get_tnum(left);
        let refined = Tnum {
            value: then_tnum.value | mask,
            mask: then_tnum.mask & !mask,
        };
        then_s.set_tnum(left, refined);

        if width == Width::W32 && bit_pos == 31 {
            if then_s.domain.fits_in_u32_range(left) {
                then_s.domain.assume_ge_imm(left, 0x80000000);
                else_s.domain.assume_le_imm(left, 0x7FFFFFFF);
            }
        } else if width == Width::W64 && bit_pos == 63 {
            then_s.domain.assume_lt_imm(left, 0);
            else_s.domain.assume_ge_imm(left, 0);
        }
    }
}

fn resolve_right_operand(
    domain: &NumericDomain,
    right: Either<Reg, i64>,
    width: Width,
    op: CmpOp,
) -> (Either<Reg, i64>, (i64, i64)) {
    let is_signed = matches!(op, CmpOp::SLt | CmpOp::SLe | CmpOp::SGt | CmpOp::SGe);

    let truncate = |val: i64| -> i64 {
        if width == Width::W32 {
            if is_signed {
                (val as u32) as i32 as i64
            } else {
                (val as u32) as i64
            }
        } else {
            val
        }
    };

    match right {
        Either::Right(imm) => {
            let eff = truncate(imm);
            (Either::Right(eff), (eff, eff))
        }
        Either::Left(reg) => {
            if let Some(val) = domain.get_fixed_value(reg) {
                let eff = truncate(val);
                (Either::Right(eff), (eff, eff))
            } else {
                let bounds = domain.get_interval(reg);
                (Either::Left(reg), bounds)
            }
        }
    }
}

fn apply_unsigned_const_fallback(
    then_s: &mut State,
    else_s: &mut State,
    left: Reg,
    op: CmpOp,
    right: Either<Reg, i64>,
) {
    let left_const = then_s.domain.get_fixed_value(left).or_else(|| {
        let t = then_s.get_tnum(left);
        if t.is_const() {
            Some(t.value as i64)
        } else {
            None
        }
    });

    match (left_const, right) {
        (Some(k), Either::Left(reg)) => {
            let flipped = flip_unsigned_cmp(op);
            apply_unsigned_range_constraint_domain(
                &mut then_s.domain,
                &mut else_s.domain,
                reg,
                flipped,
                k as u64,
            );
        }
        (_, Either::Right(imm)) => {
            apply_unsigned_range_constraint_domain(
                &mut then_s.domain,
                &mut else_s.domain,
                left,
                op,
                imm as u64,
            );
        }
        _ => {}
    }
}

fn flip_unsigned_cmp(op: CmpOp) -> CmpOp {
    match op {
        CmpOp::UGt => CmpOp::ULt,
        CmpOp::UGe => CmpOp::ULe,
        CmpOp::ULt => CmpOp::UGt,
        CmpOp::ULe => CmpOp::UGe,
        other => other,
    }
}

fn apply_unsigned_range_constraint_domain(
    then_domain: &mut NumericDomain,
    else_domain: &mut NumericDomain,
    reg: Reg,
    op: CmpOp,
    k: u64,
) {
    match op {
        CmpOp::UGt => {
            if k < u64::MAX {
                apply_signed_from_unsigned_range_domain(then_domain, reg, k + 1, u64::MAX);
            }
            apply_signed_from_unsigned_range_domain(else_domain, reg, 0, k);
        }
        CmpOp::UGe => {
            apply_signed_from_unsigned_range_domain(then_domain, reg, k, u64::MAX);
            if k > 0 {
                apply_signed_from_unsigned_range_domain(else_domain, reg, 0, k - 1);
            }
        }
        CmpOp::ULt => {
            if k > 0 {
                apply_signed_from_unsigned_range_domain(then_domain, reg, 0, k - 1);
            }
            apply_signed_from_unsigned_range_domain(else_domain, reg, k, u64::MAX);
        }
        CmpOp::ULe => {
            apply_signed_from_unsigned_range_domain(then_domain, reg, 0, k);
            if k < u64::MAX {
                apply_signed_from_unsigned_range_domain(else_domain, reg, k + 1, u64::MAX);
            }
        }
        _ => {}
    }
}

fn apply_signed_from_unsigned_range_domain(
    domain: &mut NumericDomain,
    reg: Reg,
    lo_u: u64,
    hi_u: u64,
) {
    if lo_u > hi_u {
        return;
    }

    let lo_s = lo_u as i64;
    let hi_s = hi_u as i64;

    if hi_u <= i64::MAX as u64 {
        domain.assume_ge_imm(reg, lo_s);
        domain.assume_le_imm(reg, hi_s);
    } else if lo_u >= 0x8000000000000000 {
        domain.assume_ge_imm(reg, lo_s);
        domain.assume_le_imm(reg, hi_s);
    }
}

/// jmp32 unsigned/equality narrowing for the case where the full-width
/// DBM constraint declined (`can_apply_dbm_constraint == false`) — i.e.
/// the bounds don't fit in u32 and the kernel would have narrowed the
/// `u32_min/u32_max` shadow range without affecting the upper 32 bits.
/// Mirrors `apply_w32_signed_fallback` for the unsigned/Eq/Ne ops.
fn apply_w32_unsigned_fallback(
    then_s: &mut State,
    else_s: &mut State,
    left: Reg,
    op: CmpOp,
    right: Either<Reg, i64>,
) {
    // Mirror apply_unsigned_const_fallback's symmetry: if `left` is a
    // known constant and `right` is a register, flip the op and narrow
    // `right`'s 32-bit bounds instead. Otherwise narrow `left`.
    let left_const = then_s.domain.get_fixed_value(left).or_else(|| {
        let t = then_s.get_tnum(left);
        if t.is_const() { Some(t.value as i64) } else { None }
    });

    let (target, rv, op) = match (left_const, right) {
        (Some(k), Either::Left(reg)) => (reg, k as u32, flip_unsigned_cmp(op)),
        (_, Either::Right(imm)) => (left, imm as u32, op),
        (_, Either::Left(reg)) => match then_s.domain.get_fixed_value(reg) {
            Some(v) => (left, v as u32, op),
            None => return,
        },
    };

    let (mut t_min, mut t_max) = then_s.domain.get_u32_bounds(target);
    let (mut e_min, mut e_max) = else_s.domain.get_u32_bounds(target);

    // Force the output bounds empty (signaling an infeasible branch
    // through `is_inconsistent`) for ops whose constant pins them at a
    // u32 boundary.
    let force_empty = (1u32, 0u32);

    match op {
        CmpOp::UGt => {
            if rv == u32::MAX {
                (t_min, t_max) = force_empty;
            } else {
                t_min = t_min.max(rv + 1);
            }
            e_max = e_max.min(rv);
        }
        CmpOp::UGe => {
            t_min = t_min.max(rv);
            if rv == 0 {
                (e_min, e_max) = force_empty;
            } else {
                e_max = e_max.min(rv - 1);
            }
        }
        CmpOp::ULt => {
            if rv == 0 {
                (t_min, t_max) = force_empty;
            } else {
                t_max = t_max.min(rv - 1);
            }
            e_min = e_min.max(rv);
        }
        CmpOp::ULe => {
            t_max = t_max.min(rv);
            if rv == u32::MAX {
                (e_min, e_max) = force_empty;
            } else {
                e_min = e_min.max(rv + 1);
            }
        }
        CmpOp::Eq => {
            // then: == rv ; else: != rv — boundary-bump the else side
            // (mirrors apply_cmp_to_domain's refine_ne_imm, now in the
            // u32 subreg so the kernel's `reg_set_min_max` 32-bit ≠
            // narrowing is preserved, e.g. `w2 != 6` on a `>= 6` reg
            // refines it to `>= 7`).
            t_min = t_min.max(rv);
            t_max = t_max.min(rv);
            if e_min == rv && e_min < e_max {
                e_min += 1;
            } else if e_max == rv && e_min < e_max {
                e_max -= 1;
            }
        }
        CmpOp::Ne => {
            // else: == rv ; then: != rv — boundary-bump the then side.
            e_min = e_min.max(rv);
            e_max = e_max.min(rv);
            if t_min == rv && t_min < t_max {
                t_min += 1;
            } else if t_max == rv && t_min < t_max {
                t_max -= 1;
            }
        }
        _ => return,
    }

    then_s.domain.set_u32_bounds(target, t_min, t_max);
    else_s.domain.set_u32_bounds(target, e_min, e_max);

    // Lift the refined low-32 numeric bound into the tnum mask so the
    // subsequent `<<32 >>32` zero-extension idiom that LLVM emits after
    // a W32 unsigned compare preserves the [t_min, t_max] range.
    // Kernel `__reg32_bound_offset` does this via
    // `tnum_with_subreg(reg->var_off, tnum_intersect(lo32, tnum_range(...)))`
    // (verifier.c v6.15). Without this layer, even though our u32 bounds
    // record [0, 63], the tnum's low-32 mask stays `0xffffffff`, and
    // `r5 <<= 32; r5 >>= 32` produces a tnum with mask `0xffffffff`
    // again — losing the bound at the next pointer-arithmetic check
    // (e.g. `bpf_cubic.c::bpf_cubic_cong_avoid` pc 185).
    refine_subreg_tnum(then_s, target, t_min, t_max);
    refine_subreg_tnum(else_s, target, e_min, e_max);
}

/// Intersect the low-32 bits of `target`'s tnum with `Tnum::from_range`,
/// preserving the upper 32 bits unchanged. No-op on empty/inconsistent
/// ranges (caller flags those via numeric bounds).
fn refine_subreg_tnum(state: &mut State, target: Reg, lo: u32, hi: u32) {
    if lo > hi {
        return;
    }
    let cur = state.get_tnum(target);
    let lo32_cur = Tnum {
        value: cur.value & 0xffff_ffff,
        mask: cur.mask & 0xffff_ffff,
    };
    let lo32_range = Tnum::from_range(lo as u64, hi as u64);
    let Some(lo32_new) = lo32_cur.intersect(lo32_range) else {
        return;
    };
    // Recombine: keep upper 32 bits of `cur`, replace low 32 with refined.
    let refined = Tnum {
        value: (cur.value & 0xffff_ffff_0000_0000) | (lo32_new.value & 0xffff_ffff),
        mask: (cur.mask & 0xffff_ffff_0000_0000) | (lo32_new.mask & 0xffff_ffff),
    };
    state.set_tnum(target, refined);
}

fn apply_w32_signed_fallback(
    then_s: &mut State,
    else_s: &mut State,
    left: Reg,
    op: CmpOp,
    right: Either<Reg, i64>,
) {
    // Same const-symmetry as `apply_w32_unsigned_fallback`: if `left`
    // is constant, flip the op and narrow `right` instead.
    let left_const = then_s.domain.get_fixed_value(left).or_else(|| {
        let t = then_s.get_tnum(left);
        if t.is_const() { Some(t.value as i64) } else { None }
    });

    let (target, rv, op) = match (left_const, right) {
        (Some(k), Either::Left(reg)) => (reg, k as i32, flip_signed_cmp(op)),
        (_, Either::Right(imm)) => (left, imm as i32, op),
        (_, Either::Left(reg)) => match then_s.domain.get_fixed_value(reg) {
            Some(v) => (left, v as i32, op),
            None => return,
        },
    };

    let (mut t_s32_min, mut t_s32_max) = then_s.domain.get_s32_bounds(target);
    let (mut e_s32_min, mut e_s32_max) = else_s.domain.get_s32_bounds(target);

    match op {
        CmpOp::SGt => {
            t_s32_min = t_s32_min.max(rv.saturating_add(1));
            e_s32_max = e_s32_max.min(rv);
        }
        CmpOp::SGe => {
            t_s32_min = t_s32_min.max(rv);
            e_s32_max = e_s32_max.min(rv.saturating_sub(1));
        }
        CmpOp::SLt => {
            t_s32_max = t_s32_max.min(rv.saturating_sub(1));
            e_s32_min = e_s32_min.max(rv);
        }
        CmpOp::SLe => {
            t_s32_max = t_s32_max.min(rv);
            e_s32_min = e_s32_min.max(rv.saturating_add(1));
        }
        CmpOp::Eq => {
            t_s32_min = t_s32_min.max(rv);
            t_s32_max = t_s32_max.min(rv);
        }
        _ => return,
    }

    then_s.domain.set_s32_bounds(target, t_s32_min, t_s32_max);
    else_s.domain.set_s32_bounds(target, e_s32_min, e_s32_max);
}

fn flip_signed_cmp(op: CmpOp) -> CmpOp {
    match op {
        CmpOp::SGt => CmpOp::SLt,
        CmpOp::SGe => CmpOp::SLe,
        CmpOp::SLt => CmpOp::SGt,
        CmpOp::SLe => CmpOp::SGe,
        other => other,
    }
}

fn interval_can_apply_constraint(state: &State, left: Reg, right: Either<Reg, i64>) -> bool {
    let left_is_packet = state.types.get(left).is_packet_ptr();
    let right_is_packet = match right {
        Either::Left(reg) => state.types.get(reg).is_packet_ptr(),
        Either::Right(_) => false,
    };
    if left_is_packet && right_is_packet {
        return false;
    }
    true
}
