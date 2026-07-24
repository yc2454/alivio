// src/analysis/transfer/branch/outcome.rs

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::ast::{CmpOp, Operand, Width};

/// Check if a branch condition can be determined at analysis time.
/// Returns:
///   Some(true)  - condition is ALWAYS true (only then-branch reachable)
///   Some(false) - condition is ALWAYS false (only else-branch reachable)
///   None        - condition could go either way
pub(crate) fn condition_outcome(
    state: &State,
    width: Width,
    left: Reg,
    op: CmpOp,
    right: &Operand,
) -> Option<bool> {
    let v = condition_outcome_inner(state, width, left, op, right);
    if v.is_some() && std::env::var("ZOVIA_DUMP_BRANCH_RESOLVE").ok().as_deref() == Some("1") {
        let cb = get_combined_bounds(state, left, width);
        let (s32lo, s32hi) = state.domain.get_s32_bounds(left);
        let (ilo, ihi) = state.domain.get_interval(left);
        eprintln!(
            "[branch-resolve] pc={} left={:?} op={:?} right={:?} verdict={:?} comb={:?} s32=[{},{}] ivl=[{},{}] tn={:?}",
            state.pc, left, op, right, v, cb, s32lo, s32hi, ilo, ihi, state.get_tnum(left)
        );
    }
    v
}

fn condition_outcome_inner(
    state: &State,
    width: Width,
    left: Reg,
    op: CmpOp,
    right: &Operand,
) -> Option<bool> {
    // Special case for NULL check
    if matches!(op, CmpOp::Eq | CmpOp::Ne) && matches!(right, Operand::Imm(0)) {
        let left_ty = state.types.get(left);
        if left_ty.is_null_checked() && !left_ty.is_nullable() {
            return Some(matches!(op, CmpOp::Ne));
        }
    }

    // Packet-pointer vs pkt_end: resolve a *duplicated* bounds check using
    // the kernel `mark_pkt_end` relationship (BEYOND_PKT_END / AT_PKT_END).
    // Mirrors `is_pkt_ptr_branch_taken` (verifier.c). 64-bit comparisons
    // only (packet pointers are always 64-bit). This must run BEFORE the
    // generic pointer bail below, which conservatively returns None for all
    // pointer comparisons. See `test_tc_change_tail::change_tail`.
    if width == Width::W64
        && let Some(outcome) = pkt_ptr_branch_taken(state, left, op, right) {
            return Some(outcome);
        }

    // Don't eliminate paths based on pointer comparisons
    if state.types.get(left).is_pointer() {
        return None;
    }

    // Get combined bounds from tnum and DBM
    let (min, max) = get_combined_bounds(state, left, width)?;

    match right {
        Operand::Imm(imm) => {
            let imm_val = match width {
                Width::W32 => (*imm as u32) as u64,
                Width::W64 => *imm as u64,
            };

            match op {
                CmpOp::ULt => {
                    if max < imm_val {
                        Some(true)
                    }
                    // always true
                    else if min >= imm_val {
                        Some(false)
                    }
                    // always false
                    else {
                        None
                    }
                }
                CmpOp::UGe => {
                    if min >= imm_val {
                        Some(true)
                    } else if max < imm_val {
                        Some(false)
                    } else {
                        None
                    }
                }
                CmpOp::ULe => {
                    if max <= imm_val {
                        Some(true)
                    } else if min > imm_val {
                        Some(false)
                    } else {
                        None
                    }
                }
                CmpOp::UGt => {
                    if min > imm_val {
                        Some(true)
                    } else if max <= imm_val {
                        Some(false)
                    } else {
                        None
                    }
                }
                CmpOp::Eq => {
                    if width == Width::W32 {
                        let (smin, smax) = state.domain.get_s32_bounds(left);
                        let imm_s32 = imm_val as i32;
                        if smin > imm_s32 || smax < imm_s32 {
                            return Some(false);
                        }
                    }
                    // Kernel is_scalar_branch_taken BPF_JEQ
                    // (verifier.c:16810): `if (!tnum_overlap(t1, t2))
                    // return 0;` — mutually-known bits disagreeing refute
                    // equality even when the value ranges overlap. E.g.
                    // r1 = tnum{0,0xfff8} (low 3 bits known 0)
                    // vs 0x14 (bit 2 set) — kernel resolves JNE
                    // always-taken; bounds-only arms would fall through.
                    if !tnum_overlap_imm(state, left, width, imm_val) {
                        return Some(false);
                    }
                    if min == max && min == imm_val {
                        Some(true)
                    } else if min > imm_val || max < imm_val {
                        Some(false)
                    } else {
                        None
                    }
                }
                CmpOp::Ne => {
                    if width == Width::W32 {
                        let (smin, smax) = state.domain.get_s32_bounds(left);
                        let imm_s32 = imm_val as i32;
                        if smin > imm_s32 || smax < imm_s32 {
                            return Some(true);
                        }
                    }
                    // Kernel BPF_JNE (verifier.c:16836): `if
                    // (!tnum_overlap(t1, t2)) return 1;`.
                    if !tnum_overlap_imm(state, left, width, imm_val) {
                        return Some(true);
                    }
                    if min > imm_val || max < imm_val {
                        Some(true)
                    } else if min == max && min == imm_val {
                        Some(false)
                    } else {
                        None
                    }
                }
                // Signed comparisons — compare as i64 or s32 depending on width.
                CmpOp::SLt | CmpOp::SLe | CmpOp::SGt | CmpOp::SGe => {
                    let imm_s = *imm; // signed immediate
                    if width == Width::W32 {
                        // For W32, use the s32 interpretation of the register.
                        // `get_s32_bounds` may not have tight bounds when the u64
                        // interval is in the "negative u32" quadrant (>= 0x8000_0000),
                        // so also derive bounds from the u64 combined range.
                        let (s32_lo, s32_hi) = u64_combined_to_s32(min, max)
                            .unwrap_or_else(|| {
                                let (a, b) = state.domain.get_s32_bounds(left);
                                (a as i64, b as i64)
                            });
                        let imm_s32 = imm_s as i32 as i64;
                        match op {
                            CmpOp::SGe => {
                                if s32_lo >= imm_s32 { Some(true) }
                                else if s32_hi < imm_s32 { Some(false) }
                                else { None }
                            }
                            CmpOp::SGt => {
                                if s32_lo > imm_s32 { Some(true) }
                                else if s32_hi <= imm_s32 { Some(false) }
                                else { None }
                            }
                            CmpOp::SLe => {
                                if s32_hi <= imm_s32 { Some(true) }
                                else if s32_lo > imm_s32 { Some(false) }
                                else { None }
                            }
                            CmpOp::SLt => {
                                if s32_hi < imm_s32 { Some(true) }
                                else if s32_lo >= imm_s32 { Some(false) }
                                else { None }
                            }
                            _ => unreachable!(),
                        }
                    } else {
                        // W64 signed comparison: use the register's SIGNED
                        // bounds directly. The unsigned `(min,max)` from
                        // get_combined_bounds can't serve here — a one-sided
                        // range like r0 ∈ [4, +inf] has unsigned max u64::MAX
                        // (spans the sign boundary) yet a perfectly good
                        // signed range [4, i64::MAX]. get_combined_signed_bounds
                        // returns that and stays full when truly unknown, so a
                        // const-on-left signed compare (`<const> s> <non_const>`,
                        // deducing_bounds_from_non_const_15/16) can prove the
                        // dead branch.
                        let (s64_lo, s64_hi) = get_combined_signed_bounds(state, left);
                        match op {
                            CmpOp::SGe => {
                                if s64_lo >= imm_s { Some(true) }
                                else if s64_hi < imm_s { Some(false) }
                                else { None }
                            }
                            CmpOp::SGt => {
                                if s64_lo > imm_s { Some(true) }
                                else if s64_hi <= imm_s { Some(false) }
                                else { None }
                            }
                            CmpOp::SLe => {
                                if s64_hi <= imm_s { Some(true) }
                                else if s64_lo > imm_s { Some(false) }
                                else { None }
                            }
                            CmpOp::SLt => {
                                if s64_hi < imm_s { Some(true) }
                                else if s64_lo >= imm_s { Some(false) }
                                else { None }
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                CmpOp::Test => {
                    // 1. Get the Abstract State (TNum)
                    // TNum tells us which bits are definitely 1 (value) and which are unknown (mask).
                    let mut tnum = state.get_tnum(left);

                    // 2. Handle 32-bit Width
                    // If this is a W32 check, we must ignore the upper 32 bits of the register.
                    if width == Width::W32 {
                        tnum = tnum.trunc32();
                    }

                    // 3. Check for Definite Outcomes
                    if (tnum.value & imm_val) != 0 {
                        Some(true)
                    } else if ((tnum.value | tnum.mask) & imm_val) == 0 {
                        Some(false)
                    } else {
                        None
                    }
                }
            }
        }
        Operand::Reg(r) => {
            // If the right-hand register is a known constant (via tnum
            // or single-point interval bounds), fall back to imm-comparison
            // logic. This is what lets `if r0 == r2 goto …` resolve
            // statically when r2=0 has been propagated to all linked
            // scalars (e.g. via spill/fill scalar_id fan-out).
            let rt = state.get_tnum(*r);
            let rt = if width == Width::W32 { rt.trunc32() } else { rt };
            if let Some(v) = rt.const_value() {
                let imm_op = Operand::Imm(v as i64);
                return condition_outcome(state, width, left, op, &imm_op);
            }
            let (r_lo, r_hi) = state.domain.get_interval(*r);
            if r_lo == r_hi && r_lo != i64::MIN && r_hi != i64::MAX {
                let imm_op = Operand::Imm(r_lo);
                return condition_outcome(state, width, left, op, &imm_op);
            }
            // Symmetric case: the LEFT register is a known constant, but
            // the right is the unknown one. Swap operands using the inverse
            // comparison so we can use the imm-comparison machinery against
            // the unknown side. Pattern from `verifier_bounds_deduction_non_const::
            // deducing_bounds_from_non_const_9`: `r2 = 0; if r2 > r0 ...`.
            let lt = state.get_tnum(left);
            let lt = if width == Width::W32 { lt.trunc32() } else { lt };
            let left_const = lt.const_value().map(|v| v as i64).or_else(|| {
                let (l_lo, l_hi) = state.domain.get_interval(left);
                if l_lo == l_hi && l_lo != i64::MIN && l_hi != i64::MAX {
                    Some(l_lo)
                } else {
                    None
                }
            });
            if let Some(lv) = left_const {
                let swapped = match op {
                    CmpOp::Eq | CmpOp::Ne | CmpOp::Test => op,
                    CmpOp::ULt => CmpOp::UGt,
                    CmpOp::ULe => CmpOp::UGe,
                    CmpOp::UGt => CmpOp::ULt,
                    CmpOp::UGe => CmpOp::ULe,
                    CmpOp::SLt => CmpOp::SGt,
                    CmpOp::SLe => CmpOp::SGe,
                    CmpOp::SGt => CmpOp::SLt,
                    CmpOp::SGe => CmpOp::SLe,
                };
                return condition_outcome(state, width, *r, swapped, &Operand::Imm(lv));
            }
            None
        }
    }
}

/// Resolve a `pkt OP pkt_end` (or `pkt_end OP pkt`) comparison using the
/// kernel `mark_pkt_end` relationship recorded on the packet pointer.
/// Mirrors `is_pkt_ptr_branch_taken` (verifier.c v6.15):
///
/// - `BEYOND_PKT_END`: pkt has ≥1 byte beyond pkt_end ⇒ `pkt > end` true,
///   `pkt <= end` false, `pkt >= end` true, `pkt < end` false.
/// - `AT_PKT_END`: pkt == pkt_end ⇒ only `pkt >= end` / `pkt < end`
///   resolve (`>=` true, `<` false); `>` / `<=` stay unknown.
///
/// Returns `Some(true)` if the branch is always taken, `Some(false)` if
/// never taken, `None` if undetermined.
fn pkt_ptr_branch_taken(
    state: &State,
    left: Reg,
    op: CmpOp,
    right: &Operand,
) -> Option<bool> {
    use crate::analysis::machine::reg_types::RegType;
    use crate::domains::interval::PktEndRel;
    use crate::domains::numeric::NumericDomain;

    let Operand::Reg(right_reg) = right else {
        return None;
    };
    let right_reg = *right_reg;

    let left_ty = state.types.get(left);
    let right_ty = state.types.get(right_reg);

    // Normalize so `pkt_reg` is the packet pointer and `op` is written as
    // `pkt OP pkt_end`. If pkt_end is on the left, flip the comparison.
    let (pkt_reg, op) = if matches!(right_ty, RegType::PtrToPacketEnd)
        && matches!(left_ty, RegType::PtrToPacket)
    {
        (left, op)
    } else if matches!(left_ty, RegType::PtrToPacketEnd)
        && matches!(right_ty, RegType::PtrToPacket)
    {
        (right_reg, flip_cmp_op(op))
    } else {
        return None;
    };

    let rel = match state.domain {
        NumericDomain::Interval(ref ivl) => ivl.get_ptr_offset(pkt_reg).and_then(|po| po.pkt_end_rel),
        _ => None,
    }?;

    // Kernel `is_pkt_ptr_branch_taken`: only the unsigned pkt comparisons
    // are modeled. `pkt->range < 0` is implied by `rel` being set.
    let verdict = match op {
        // `pkt > end` / `pkt <= end`: resolvable only when BEYOND.
        CmpOp::UGt | CmpOp::ULe => match rel {
            PktEndRel::Beyond => Some(op == CmpOp::UGt),
            PktEndRel::At => None,
        },
        // `pkt >= end` / `pkt < end`: resolvable for BEYOND and AT.
        CmpOp::UGe | CmpOp::ULt => match rel {
            PktEndRel::Beyond | PktEndRel::At => Some(op == CmpOp::UGe),
        },
        _ => None,
    };
    if std::env::var("ZOVIA_DUMP_PKTEND").ok().as_deref() == Some("1") {
        eprintln!("[pktend-resolve] pc={} reg={:?} op={:?} rel={:?} verdict={:?}",
            state.pc, pkt_reg, op, rel, verdict);
    }
    verdict
}

/// Flip a comparison operator's operands (kernel `flip_opcode`): rewrite
/// `a OP b` as `b FLIP(OP) a`. Only the orderings used by packet-pointer
/// comparisons matter here; equality/JSET are unaffected by swapping.
fn flip_cmp_op(op: CmpOp) -> CmpOp {
    match op {
        CmpOp::UGt => CmpOp::ULt,
        CmpOp::ULt => CmpOp::UGt,
        CmpOp::UGe => CmpOp::ULe,
        CmpOp::ULe => CmpOp::UGe,
        CmpOp::SGt => CmpOp::SLt,
        CmpOp::SLt => CmpOp::SGt,
        CmpOp::SGe => CmpOp::SLe,
        CmpOp::SLe => CmpOp::SGe,
        CmpOp::Eq | CmpOp::Ne | CmpOp::Test => op,
    }
}

/// Convert u64 combined bounds (from `get_combined_bounds` for W32) to a signed
/// i64 range representing the s32 interpretation of those u32 values.
/// Returns None if the range spans the u32 sign boundary (0x7FFF_FFFF → 0x8000_0000),
/// since the signed range would then be the whole i32 domain.
fn u64_combined_to_s32(min: u64, max: u64) -> Option<(i64, i64)> {
    if min > 0xFFFF_FFFF || max > 0xFFFF_FFFF {
        return None; // not a u32 range
    }
    let lo_u32 = min as u32;
    let hi_u32 = max as u32;
    // Does the range cross the sign boundary?
    if lo_u32 <= 0x7FFF_FFFF && hi_u32 >= 0x8000_0000 {
        return None;
    }
    Some((lo_u32 as i32 as i64, hi_u32 as i32 as i64))
}

/// Kernel `tnum_overlap` (tnum.c:162): the mutually-known bits of the two
/// tnums must agree, else the values can never be equal. Width-aware:
/// jmp32 compares the subreg tnums (kernel is_scalar_branch_taken uses
/// tnum_subreg(t) for is_jmp32).
fn tnum_overlap_imm(state: &State, reg: Reg, width: Width, imm_val: u64) -> bool {
    let t = match width {
        Width::W32 => state.get_tnum(reg).trunc32(),
        Width::W64 => state.get_tnum(reg),
    };
    let mu = !t.mask; // imm is fully known
    (t.value & mu) == (imm_val & mu)
}

/// Get combined bounds from tnum and DBM, as unsigned values.
/// Returns None if we can't safely determine bounds.
pub(crate) fn get_combined_bounds(state: &State, reg: Reg, width: Width) -> Option<(u64, u64)> {
    // Tnum bounds
    let tnum = match width {
        Width::W32 => state.get_tnum(reg).trunc32(),
        Width::W64 => state.get_tnum(reg),
    };
    let tnum_min = tnum.min_value();
    let tnum_max = tnum.max_value();

    // Interval-domain bounds (kernel-mode: the Interval domain; legacy
    // names `dbm_*`). `get_interval` returns signed i64 bounds with
    // i64::MIN / i64::MAX standing for "unbounded". A one-SIDED bound is
    // still useful: e.g. after `if r0 < 3` the fall-through has the
    // interval [3, i64::MAX] — the finite lower bound 3 proves `r0 == 2`
    // is unsatisfiable even though the upper bound is unknown. The earlier
    // all-or-nothing gate (`dbm_lo != MIN && dbm_hi != MAX`) discarded the
    // whole interval whenever EITHER side was open, dropping that lower
    // bound and falling back to the unconstrained tnum (0..U64_MAX), so
    // `condition_outcome` couldn't prove the dead branch
    // (verifier_bounds_deduction_non_const::* + the USDT progs).
    //
    // Intersect each side independently. An interval bound is only a valid
    // UNSIGNED bound when it is non-negative; a negative signed bound says
    // nothing about the unsigned magnitude (the value could be a large
    // u64), so leave that side to the tnum.
    // For a W32 comparison the relevant interval is the register's u32
    // sub-bounds (the low 32 bits the branch narrows), NOT the 64-bit
    // interval — after `if w0 < 4` the u32 bounds are [4, U32_MAX] while
    // the 64-bit interval stays unbounded (upper 32 bits unknown).
    let (dbm_lo, dbm_hi): (i64, i64) = if width == Width::W32 {
        let (u_lo, u_hi) = state.domain.get_u32_bounds(reg);
        (u_lo as i64, u_hi as i64)
    } else {
        state.domain.get_interval(reg)
    };

    let mut lo = tnum_min;
    let mut hi = tnum_max;

    // Dedicated u64 bounds (kernel umin/umax). Carries the `!= 0`
    // edge-bump (refine_ne_imm's unsigned pair) that neither the tnum
    // nor the signed interval can represent for a full-range scalar —
    // without this channel the later `if reg != 0` retest cannot fold
    // and the dead ==0 arm gets walked (the pc2917 phantom corridor).
    if width == Width::W64 {
        let (u_lo, u_hi) = state.domain.get_u64_bounds(reg);
        lo = lo.max(u_lo);
        hi = hi.min(u_hi);
    }

    if dbm_lo != i64::MIN && dbm_lo >= 0 {
        lo = lo.max(dbm_lo as u64);
    }
    if dbm_hi != i64::MAX && dbm_hi >= 0 {
        let dbm_max = dbm_hi as u64;
        // For W32, an interval upper bound outside u32 range is not a
        // tighter u32 bound — ignore it (keep the tnum's u32-truncated max).
        if !(width == Width::W32 && dbm_max > 0xFFFF_FFFF) {
            hi = hi.min(dbm_max);
        }
    }

    // Sanity: if the per-side intersection inverted the range (shouldn't
    // happen for consistent bounds), fall back to the tnum range.
    if lo <= hi {
        Some((lo, hi))
    } else {
        Some((tnum_min, tnum_max))
    }
}

pub(crate) fn fits_in_i32(bounds: (i64, i64)) -> bool {
    bounds.0 >= i32::MIN as i64 && bounds.1 <= i32::MAX as i64
}

pub(crate) fn fits_in_u32(bounds: (i64, i64)) -> bool {
    bounds.0 >= 0 && bounds.1 <= 0xFFFFFFFF
}

/// Get combined signed bounds for a register using both DBM and tnum.
/// Returns (lo, hi) as signed i64 values, using the tighter bound from each source.
pub(crate) fn get_combined_signed_bounds(state: &State, reg: Reg) -> (i64, i64) {
    let (dbm_lo, dbm_hi) = state.domain.get_interval(reg);
    let tnum = state.get_tnum(reg);
    let tnum_min = tnum.min_value();
    let tnum_max = tnum.max_value();

    let lo = if tnum_min > i64::MAX as u64 {
        let tnum_lo = tnum_min as i64;
        if dbm_lo != i64::MIN {
            dbm_lo.max(tnum_lo)
        } else {
            tnum_lo
        }
    } else {
        dbm_lo
    };

    let hi = if tnum_max <= i64::MAX as u64 {
        let tnum_hi = tnum_max as i64;
        if dbm_hi != i64::MAX {
            dbm_hi.min(tnum_hi)
        } else {
            tnum_hi
        }
    } else {
        dbm_hi
    };

    (lo, hi)
}
