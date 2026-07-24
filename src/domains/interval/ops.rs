// Interval domain operations
//
// Implements the abstract operations for the interval domain.
// These mirror the zone/ops.rs interface but without relational constraints.

use super::state::{IntervalState, PtrOffset, RegInterval, ScalarBounds};
use crate::analysis::machine::reg_types::new_ptr_id;
use crate::analysis::machine::reg::Reg;

// ══════════════════════════════════════════════════════════════════════════════
//  Query & Interval Analysis
// ══════════════════════════════════════════════════════════════════════════════

/// Extracts the interval [lower_bound, upper_bound] for a register
pub fn get_interval(state: &IntervalState, x: Reg) -> (i64, i64) {
    state.get_interval(x)
}

/// Returns the interval of the distance between two registers
/// For interval domain, this is conservative unless both are pointers to same anchor
pub fn get_distance_interval(state: &IntervalState, x: Reg, y: Reg) -> (i64, i64) {
    // Trivial case: distance from a register to itself is always 0
    if x == y {
        return (0, 0);
    }

    // Check if both registers have pointer offset info to the same anchor
    let x_off = state.get_ptr_offset(x);
    let y_off = state.get_ptr_offset(y);

    match (x_off, y_off) {
        (Some(xo), Some(yo)) if xo.anchor == yo.anchor => {
            // Both point to same anchor - can compute distance
            let min_diff = xo.off.saturating_sub(yo.max_offset());
            let max_diff = xo.max_offset().saturating_sub(yo.off);
            (min_diff, max_diff)
        }
        _ => {
            // Cannot determine relationship - return conservative bounds
            // Try to use scalar bounds
            let (x_min, x_max) = state.get_interval(x);
            let (y_min, y_max) = state.get_interval(y);

            if x_min != i64::MIN && x_max != i64::MAX && y_min != i64::MIN && y_max != i64::MAX {
                (x_min.saturating_sub(y_max), x_max.saturating_sub(y_min))
            } else {
                (i64::MIN, i64::MAX)
            }
        }
    }
}

/// Returns the exact distance between two registers if constant
pub fn get_distance_fixed(state: &IntervalState, x: Reg, y: Reg) -> Option<i64> {
    let (lo, hi) = get_distance_interval(state, x, y);
    if lo == hi && lo != i64::MIN && lo != i64::MAX {
        Some(lo)
    } else {
        None
    }
}

/// Returns the fixed concrete value of a register if constant
pub fn get_fixed_value(state: &IntervalState, x: Reg) -> Option<i64> {
    state.get_fixed_value(x)
}

// ══════════════════════════════════════════════════════════════════════════════
//  Predicates & Proofs
// ══════════════════════════════════════════════════════════════════════════════

/// Returns true if the register is proven to be exactly zero
pub fn proven_zero(state: &IntervalState, x: Reg) -> bool {
    state.get_bounds(x).is_zero()
}

/// Returns true if the register is proven to be >= 0
pub fn proven_nonnegative(state: &IntervalState, x: Reg) -> bool {
    state.get_bounds(x).is_nonnegative()
}

/// Returns true if the register is proven to be > 0
pub fn proven_positive(state: &IntervalState, x: Reg) -> bool {
    state.get_bounds(x).is_positive()
}

/// Returns true if a register is proven to be in the u32 range [0, 2^32-1]
pub fn proven_u32_range(state: &IntervalState, v: Reg) -> bool {
    state.get_bounds(v).is_u32()
}

// ══════════════════════════════════════════════════════════════════════════════
//  Value Assignments
// ══════════════════════════════════════════════════════════════════════════════

/// Removes all constraints related to the specified register
pub fn forget(state: &mut IntervalState, x: Reg) {
    state.forget(x);
}

/// Overwrites a register with a specific constant value
pub fn assign_imm(state: &mut IntervalState, x: Reg, imm: i64) {
    if x != Reg::Zero && !x.is_anchor() {
        state.set(x, RegInterval::constant(imm));
    }
}

/// Overwrites a register with zero
pub fn assign_zero(state: &mut IntervalState, x: Reg) {
    assign_imm(state, x, 0);
}

/// Overwrites a register with the value of another register
pub fn assign_reg(state: &mut IntervalState, x: Reg, y: Reg) {
    if x != Reg::Zero && !x.is_anchor() {
        state.set(x, state.get(y).clone());
    }
}

/// Intersect x's bounds with y's (constraint form of `x == y`). Used by
/// `if x == y` branch refinement; the result's emptiness is observable
/// through `is_inconsistent`.
pub fn intersect_eq_reg(state: &mut IntervalState, x: Reg, y: Reg) {
    if x == Reg::Zero || x.is_anchor() {
        return;
    }
    let yb = state.get(y).bounds.clone();
    let xb = &mut state.get_bounds_mut(x);
    xb.smin = xb.smin.max(yb.smin);
    xb.smax = xb.smax.min(yb.smax);
    xb.umin = xb.umin.max(yb.umin);
    xb.umax = xb.umax.min(yb.umax);
    // 8-bound: intersect the 32-bit halves the same way + sync.
    xb.s32_min = xb.s32_min.max(yb.s32_min);
    xb.s32_max = xb.s32_max.min(yb.s32_max);
    xb.u32_min = xb.u32_min.max(yb.u32_min);
    xb.u32_max = xb.u32_max.min(yb.u32_max);
    xb.sync_bounds();
}

/// Establishes the relationship dst = src + imm
pub fn assign_reg_offset(state: &mut IntervalState, dst: Reg, src: Reg, imm: i64) {
    if dst == Reg::Zero || dst.is_anchor() {
        return;
    }

    let src_interval = state.get(src).clone();
    let mut new_bounds = ScalarBounds {
        smin: src_interval.bounds.smin.saturating_add(imm),
        smax: src_interval.bounds.smax.saturating_add(imm),
        umin: src_interval.bounds.umin.saturating_add(imm as u64),
        umax: src_interval.bounds.umax.saturating_add(imm as u64),
        scalar_id: None, // Arithmetic breaks scalar relationship
        ..ScalarBounds::unknown()
    };
    // 8-bound: derive 32-bit halves from the post-add 64-bit.
    new_bounds.forget_32_then_sync();

    // Preserve pointer offset info, adjusting the fixed offset
    // Also preserve range if set, adjusting for the offset change
    let new_ptr_offset = src_interval.ptr_offset.map(|po| PtrOffset {
        anchor: po.anchor,
        off: po.off.saturating_add(imm),
        var_off: po.var_off,
        // Adjust range: if we had range=8 and add offset=2, new range=6
        range: po.range.map(|r| r.saturating_sub(imm)),
        // id propagates: a constant offset adjustment leaves the
        // pointer in the same kernel-style identity family.
        id: po.id,
        // Any arithmetic shifts the pointer relative to pkt_end, so the
        // mark_pkt_end relationship no longer holds for the result.
        pkt_end_rel: None,
    });

    state.set(
        dst,
        RegInterval {
            bounds: new_bounds,
            ptr_offset: new_ptr_offset,
        },
    );
}

/// Initializes a register as a map value pointer at offset 0
/// This sets up PtrOffset tracking for bounds checking
pub fn init_map_value_ptr(state: &mut IntervalState, reg: Reg) {
    if reg == Reg::Zero || reg.is_anchor() {
        return;
    }

    // Use Reg::Zero as a synthetic anchor for map values
    // This allows us to track offset from buffer start
    state.set(
        reg,
        RegInterval {
            // Kernel model (verifier.c adjust_ptr_min_max_vals /
            // reg_bounds_sync): a map-value pointer reg's
            // smin/smax/umin/umax track its *offset*, which is 0 for a
            // fresh lookup result. refine_map reads
            // get_interval(base).smin as min_off; leaving this unknown()
            // gave min_off=i64::MIN -> spurious low-side disjunct ->
            // cvc5 declines -> "Unbounded variable map access".
            bounds: ScalarBounds::constant(0),
            ptr_offset: Some(PtrOffset {
                anchor: Reg::Zero, // Synthetic anchor for map values
                off: 0,
                var_off: 0,
                range: None,
                id: None,
                pkt_end_rel: None,
            }),
        },
    );
}

/// Like `init_map_value_ptr` but the pointer starts at a fixed `offset`
/// from the map value's start (a direct LD_IMM64 BPF_PSEUDO_MAP_VALUE /
/// .bss/.data/.rodata global is at its section offset, not 0). The bounds
/// (which the kernel/refine_map model as the pointer's offset) and the
/// PtrOffset.off both carry `offset`, so a subsequent `ptr += bounded_idx`
/// produces a checkable [offset+idx_min, offset+idx_max] range in
/// `interval_check_map_access`. Seeding 0 here would be UNSOUND — it would
/// under-count the offset of a nonzero-offset global and accept an access
/// past value_size.
pub fn init_map_value_ptr_at(state: &mut IntervalState, reg: Reg, offset: i64) {
    if reg == Reg::Zero || reg.is_anchor() {
        return;
    }
    state.set(
        reg,
        RegInterval {
            bounds: ScalarBounds::constant(offset),
            ptr_offset: Some(PtrOffset {
                anchor: Reg::Zero,
                off: offset,
                var_off: 0,
                range: None,
                id: None,
                pkt_end_rel: None,
            }),
        },
    );
}

/// Assigns a concrete interval to a register
pub fn assign_interval(state: &mut IntervalState, r: Reg, min: i64, max: i64) {
    if r != Reg::Zero && !r.is_anchor() {
        state.set(
            r,
            RegInterval {
                bounds: {
                    let mut b = ScalarBounds {
                        smin: min,
                        smax: max,
                        umin: if min >= 0 { min as u64 } else { 0 },
                        umax: if max >= 0 { max as u64 } else { u64::MAX },
                        scalar_id: None,
                        ..ScalarBounds::unknown()
                    };
                    b.forget_32_then_sync();
                    b
                },
                ptr_offset: None,
            },
        );
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Arithmetic Transformations
// ══════════════════════════════════════════════════════════════════════════════

/// Performs dst += imm
pub fn apply_add_imm(state: &mut IntervalState, dst: Reg, imm: i64) {
    if dst == Reg::Zero || dst.is_anchor() {
        return;
    }

    let bounds = state.get_bounds_mut(dst);

    // Kernel-faithful wrap-detection. Mirrors `scalar_min_max_add` in
    // verifier.c v6.15 (~L13700): if `min + imm` and `max + imm` don't
    // agree on overflow, the post-op range straddles the wrap boundary
    // (two disjoint pieces in unsigned modular arithmetic) and can't be
    // represented by a single contiguous interval. The kernel resets
    // such ranges to the full domain instead of using saturating
    // arithmetic, which silently produces inconsistent (min > max)
    // bounds when later constraints intersect with the wrong piece.
    //
    // Concrete: r1 ∈ u32 [0, 0xFFFFFFFF], r1 += -4 with saturating_add
    // produced umin=0xFFF..FFFC (no overflow), umax=u64::MAX
    // (saturated from overflow). A subsequent `umax := min(umax, 1)`
    // then leaves umin > umax and the whole state is dropped as
    // infeasible — wrongly excluding the kernel-reachable case where
    // r1 was 4 or 5 (so r1-4 ∈ {0, 1}).
    //
    // We do separate overflow checks for the four bound pairs: u64
    // (umin/umax) and i64 (smin/smax) for the 64-bit halves, plus u32
    // (u32_min/u32_max) and i32 (s32_min/s32_max) for the 32-bit
    // halves. Each pair is reset to its full domain independently
    // when wrap-disagreement is detected.
    let imm_u64 = imm as u64;
    let (new_umin, ovf_umin) = bounds.umin.overflowing_add(imm_u64);
    let (new_umax, ovf_umax) = bounds.umax.overflowing_add(imm_u64);
    if ovf_umin == ovf_umax {
        bounds.umin = new_umin;
        bounds.umax = new_umax;
    } else {
        bounds.umin = 0;
        bounds.umax = u64::MAX;
    }
    let (new_smin, ovf_smin) = bounds.smin.overflowing_add(imm);
    let (new_smax, ovf_smax) = bounds.smax.overflowing_add(imm);
    if ovf_smin == ovf_smax {
        bounds.smin = new_smin;
        bounds.smax = new_smax;
    } else {
        bounds.smin = i64::MIN;
        bounds.smax = i64::MAX;
    }
    bounds.scalar_id = None; // Arithmetic breaks scalar relationship

    // 32-bit halves: mirror `adjust_scalar_min_max_vals` 32-bit path.
    // Same wrap-disagreement reset as the 64-bit pairs above.
    let imm32_u = imm as u32;
    let imm32_s = imm as i32;
    let (new_u32_min, ovf_u32_min) = bounds.u32_min.overflowing_add(imm32_u);
    let (new_u32_max, ovf_u32_max) = bounds.u32_max.overflowing_add(imm32_u);
    if ovf_u32_min == ovf_u32_max {
        bounds.u32_min = new_u32_min;
        bounds.u32_max = new_u32_max;
    } else {
        bounds.u32_min = 0;
        bounds.u32_max = u32::MAX;
    }
    let (new_s32_min, ovf_s32_min) = bounds.s32_min.overflowing_add(imm32_s);
    let (new_s32_max, ovf_s32_max) = bounds.s32_max.overflowing_add(imm32_s);
    if ovf_s32_min == ovf_s32_max {
        bounds.s32_min = new_s32_min;
        bounds.s32_max = new_s32_max;
    } else {
        bounds.s32_min = i32::MIN;
        bounds.s32_max = i32::MAX;
    }
    bounds.sync_bounds();
    if std::env::var("ZOVIA_DBG_ADDIMM").ok().as_deref() == Some("1") {
        eprintln!(
            "[addimm] dst={:?} imm={} post s=[{},{}] u=[{:#x},{:#x}] s32=[{},{}] u32=[{:#x},{:#x}]",
            dst, imm, bounds.smin, bounds.smax, bounds.umin, bounds.umax,
            bounds.s32_min, bounds.s32_max, bounds.u32_min, bounds.u32_max
        );
    }

    // Update pointer offset if present
    if let Some(ref mut po) = state.get_mut(dst).ptr_offset {
        po.off = po.off.saturating_add(imm);
        // Adjust range: adding to offset decreases remaining safe range
        po.range = po.range.map(|r| r.saturating_sub(imm));
        // Kernel: "something was added to pkt_ptr, set range to zero" —
        // the AT/BEYOND_PKT_END sentinel does NOT survive pointer
        // arithmetic (adjust_ptr_min_max_vals resets reg->range), so a
        // re-advanced pointer's dup-check is NOT statically resolvable.
        // Keeping it stale would prune ext-header re-check paths
        // the kernel walks (FA-risk in base mode).
        po.pkt_end_rel = None;
    }
}

/// Performs dst += src
pub fn apply_add_reg(state: &mut IntervalState, dst: Reg, src: Reg) {
    if dst == Reg::Zero || dst.is_anchor() {
        return;
    }

    let src_bounds = state.get_bounds(src).clone();
    let dst_bounds = state.get_bounds_mut(dst);

    // Add intervals: [a, b] + [c, d] = [a+c, b+d]
    dst_bounds.smin = dst_bounds.smin.saturating_add(src_bounds.smin);
    dst_bounds.smax = dst_bounds.smax.saturating_add(src_bounds.smax);
    dst_bounds.umin = dst_bounds.umin.saturating_add(src_bounds.umin);
    dst_bounds.umax = dst_bounds.umax.saturating_add(src_bounds.umax);
    dst_bounds.scalar_id = None; // Arithmetic breaks scalar relationship
    // 8-bound: 32-bit halves added with 32-bit saturation. The
    // saturating add on i32/u32 keeps the 32-bit view tight for
    // values that don't wrap past 32 bits; reg_bounds_sync below
    // then back-derives tighter values when the 64-bit upper bits
    // stayed constant.
    dst_bounds.u32_min = dst_bounds.u32_min.saturating_add(src_bounds.u32_min);
    dst_bounds.u32_max = dst_bounds.u32_max.saturating_add(src_bounds.u32_max);
    dst_bounds.s32_min = dst_bounds.s32_min.saturating_add(src_bounds.s32_min);
    dst_bounds.s32_max = dst_bounds.s32_max.saturating_add(src_bounds.s32_max);
    dst_bounds.sync_bounds();

    // Adding variable destroys fixed pointer offset precision
    // But we can preserve if src is constant
    if let Some(src_const) = src_bounds.get_constant() {
        if let Some(ref mut po) = state.get_mut(dst).ptr_offset {
            po.off = po.off.saturating_add(src_const);
            // Adjust range: adding to offset decreases remaining safe range
            po.range = po.range.map(|r| r.saturating_sub(src_const));
            // id preserved: constant add stays in the same chain.
            po.pkt_end_rel = None; // kernel zeroes range on pkt-ptr add
        }
    } else {
        // Variable addition: use signed bounds to properly track negative offsets
        // The signed range [smin, smax] correctly represents the possible values
        if let Some(ref mut po) = state.get_mut(dst).ptr_offset {
            // Add smin to base offset (handles negative values correctly)
            po.off = po.off.saturating_add(src_bounds.smin);
            // Add the signed range width to var_off (use saturating_sub to avoid overflow)
            let signed_range = src_bounds.smax.saturating_sub(src_bounds.smin);
            if signed_range >= 0 {
                po.var_off = po.var_off.saturating_add(signed_range as u64);
            }
            // Adding variable invalidates proven range
            po.range = None;
            po.pkt_end_rel = None; // kernel zeroes range on pkt-ptr add
            // Mint a fresh kernel-style id when this is the first time
            // the pointer picks up a variable offset; otherwise the
            // existing chain absorbs the new variability.
            if po.id.is_none() {
                po.id = Some(new_ptr_id());
            }
        }
    }
}

/// Performs dst = scalar_dst + ptr_src
/// Creates a new PtrOffset for dst combining ptr's offset with scalar's range
/// scalar_lo and scalar_hi are the bounds of the scalar before the add
pub fn apply_scalar_add_ptr(
    state: &mut IntervalState,
    dst: Reg,
    ptr_src: Reg,
    scalar_lo: i64,
    scalar_hi: i64,
) {
    if dst == Reg::Zero || dst.is_anchor() {
        return;
    }

    // Get the ptr's PtrOffset
    let ptr_offset = state.get_ptr_offset(ptr_src).cloned();

    // Forget dst's current state
    state.forget(dst);

    // If ptr has PtrOffset, create new PtrOffset for dst
    if let Some(po) = ptr_offset {
        // The scalar range adds to the pointer's var_off
        let scalar_range = if scalar_hi >= scalar_lo {
            (scalar_hi - scalar_lo) as u64
        } else {
            0
        };

        // New offset combines ptr's offset with scalar's minimum
        // New var_off combines both variable ranges
        let new_off = po.off.saturating_add(scalar_lo);
        let new_var_off = po.var_off.saturating_add(scalar_range);

        // Inherit the source pointer's id when it already has one
        // (we're extending an existing chain). When it doesn't, mint
        // a fresh id only if the scalar contributes variability —
        // a constant add (scalar_lo == scalar_hi) keeps id None.
        let new_id = if po.id.is_some() {
            po.id
        } else if scalar_range > 0 {
            Some(new_ptr_id())
        } else {
            None
        };

        state.set(
            dst,
            RegInterval {
                bounds: ScalarBounds::unknown(), // Absolute address still unknown
                ptr_offset: Some(PtrOffset {
                    anchor: po.anchor,
                    off: new_off,
                    var_off: new_var_off,
                    // Adding variable invalidates proven range
                    range: None,
                    id: new_id,
                    pkt_end_rel: None,
                }),
            },
        );
    }
}

/// Performs dst -= src
pub fn apply_sub_reg(state: &mut IntervalState, dst: Reg, src: Reg) {
    if dst == Reg::Zero || dst.is_anchor() {
        return;
    }

    let src_bounds = state.get_bounds(src).clone();
    let dst_bounds = state.get_bounds_mut(dst);

    // Subtract intervals: [a, b] - [c, d] = [a-d, b-c]
    dst_bounds.smin = dst_bounds.smin.saturating_sub(src_bounds.smax);
    dst_bounds.smax = dst_bounds.smax.saturating_sub(src_bounds.smin);
    dst_bounds.umin = dst_bounds.umin.saturating_sub(src_bounds.umax);
    dst_bounds.umax = dst_bounds.umax.saturating_sub(src_bounds.umin);
    dst_bounds.scalar_id = None; // Arithmetic breaks scalar relationship
    // 8-bound: 32-bit halves subtracted with 32-bit saturation;
    // sync_bounds derives further tightening from 64-bit.
    dst_bounds.u32_min = dst_bounds.u32_min.saturating_sub(src_bounds.u32_max);
    dst_bounds.u32_max = dst_bounds.u32_max.saturating_sub(src_bounds.u32_min);
    dst_bounds.s32_min = dst_bounds.s32_min.saturating_sub(src_bounds.s32_max);
    dst_bounds.s32_max = dst_bounds.s32_max.saturating_sub(src_bounds.s32_min);
    dst_bounds.sync_bounds();

    // Update pointer offset if present: ptr -= [smin, smax]
    // Minimum offset after sub: off - smax
    // Maximum offset after sub: off + var_off - smin
    // So new_off = off - smax, new_var_off = var_off + (smax - smin)
    if let Some(ref mut po) = state.get_mut(dst).ptr_offset {
        po.off = po.off.saturating_sub(src_bounds.smax);
        // Use saturating_sub to avoid overflow when range is very large
        let signed_range = src_bounds.smax.saturating_sub(src_bounds.smin);
        if signed_range >= 0 {
            po.var_off = po.var_off.saturating_add(signed_range as u64);
        }
        po.range = None;
        po.pkt_end_rel = None; // kernel zeroes range on pkt-ptr arithmetic
    }
}

/// Performs dst &= mask (0 <= result <= mask for non-negative mask)
pub fn apply_and_imm(state: &mut IntervalState, dst: Reg, mask: i64) {
    if dst == Reg::Zero || dst.is_anchor() {
        return;
    }

    // AND with mask bounds result to [0, mask] for non-negative mask
    let bounds = state.get_bounds_mut(dst);
    if mask >= 0 {
        bounds.smin = 0;
        bounds.smax = mask;
        bounds.umin = 0;
        bounds.umax = mask as u64;
        bounds.scalar_id = None; // Arithmetic breaks scalar relationship
        // 8-bound: AND constrains the low 32 bits too. For mask
        // fitting in u32, the 32-bit halves are also [0, mask].
        // Otherwise reset+sync derives what it can.
        bounds.forget_32_then_sync();
    } else {
        // Negative mask - conservative
        *bounds = ScalarBounds::unknown();
    }

    // AND destroys pointer relationship
    state.get_mut(dst).ptr_offset = None;
}

/// Performs dst *= imm
pub fn apply_mul_imm(state: &mut IntervalState, dst: Reg, imm: i64) {
    if dst == Reg::Zero || dst.is_anchor() {
        return;
    }

    if imm == 0 {
        assign_zero(state, dst);
        return;
    }

    if imm == 1 {
        return;
    }

    let bounds = state.get_bounds(dst).clone();

    if imm > 0 {
        // Positive multiplier preserves sign
        let mut new_bounds = ScalarBounds {
            smin: bounds.smin.saturating_mul(imm),
            smax: bounds.smax.saturating_mul(imm),
            umin: bounds.umin.saturating_mul(imm as u64),
            umax: bounds.umax.saturating_mul(imm as u64),
            scalar_id: None, // Arithmetic breaks scalar relationship
            ..ScalarBounds::unknown()
        };
        // 8-bound: reset 32-bit halves to full and let sync_bounds
        // derive tight values from the post-mul 64-bit bounds.
        new_bounds.forget_32_then_sync();
        state.get_bounds_mut(dst).clone_from(&new_bounds);
    } else {
        // Negative multiplier - go conservative
        forget(state, dst);
        return;
    }

    // Multiplication destroys pointer relationship
    state.get_mut(dst).ptr_offset = None;
}

/// Performs reg /= imm
pub fn apply_div_imm(state: &mut IntervalState, reg: Reg, imm: i64) {
    if reg == Reg::Zero || reg.is_anchor() || imm == 0 {
        return;
    }

    let bounds = state.get_bounds(reg).clone();

    // Only handle positive divisor with non-negative dividend
    if imm > 0 && bounds.smin >= 0 {
        let mut new_bounds = ScalarBounds {
            smin: bounds.smin / imm,
            smax: bounds.smax / imm,
            umin: bounds.umin / (imm as u64),
            umax: bounds.umax / (imm as u64),
            scalar_id: None, // Arithmetic breaks scalar relationship
            ..ScalarBounds::unknown()
        };
        new_bounds.forget_32_then_sync();
        state.get_bounds_mut(reg).clone_from(&new_bounds);
    } else {
        forget(state, reg);
        return;
    }

    // Division destroys pointer relationship
    state.get_mut(reg).ptr_offset = None;
}

/// Performs dst /= src (conservative: forgets destination)
pub fn apply_div_reg(state: &mut IntervalState, dst: Reg) {
    forget(state, dst);
}

/// Performs reg = -reg
pub fn apply_neg(state: &mut IntervalState, reg: Reg) {
    if reg == Reg::Zero || reg.is_anchor() {
        return;
    }

    let bounds = state.get_bounds(reg).clone();

    // Handle edge cases that would cause inconsistent bounds after negation:
    // - i64::MIN cannot be negated (overflow: -i64::MIN = i64::MIN)
    // - Wide ranges spanning both positive and negative may produce smin > smax
    if bounds.smin == i64::MIN || bounds.smax == i64::MIN {
        // Cannot safely negate i64::MIN, go conservative
        forget(state, reg);
        return;
    }

    // For well-behaved ranges, negate swaps the bounds
    // -[a, b] = [-b, -a]
    let neg_smax = bounds.smin.wrapping_neg();
    let neg_smin = bounds.smax.wrapping_neg();

    // Safety check: ensure bounds are still valid after negation
    if neg_smin > neg_smax {
        forget(state, reg);
        return;
    }

    let mut new_bounds = ScalarBounds {
        smin: neg_smin,
        smax: neg_smax,
        umin: 0, // Conservative for unsigned after negation
        umax: u64::MAX,
        scalar_id: None, // Arithmetic breaks scalar relationship
        ..ScalarBounds::unknown()
    };
    new_bounds.forget_32_then_sync();
    state.get_bounds_mut(reg).clone_from(&new_bounds);

    // Negation destroys pointer relationship
    state.get_mut(reg).ptr_offset = None;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Constraint Refinement (Branch conditions)
// ══════════════════════════════════════════════════════════════════════════════

/// Assumes x <= y
pub fn assume_le(state: &mut IntervalState, x: Reg, y: Reg) {
    let y_max = state.get_bounds(y).smax;
    let x_min = state.get_bounds(x).smin;
    let x_smin = state.get_bounds(x).smin;
    let y_smax = state.get_bounds(y).smax;

    // Only apply constraints if they won't create inconsistent bounds
    // x <= y means x <= y_max, but only if that doesn't go below x_min
    if y_max >= x_smin {
        state.get_bounds_mut(x).assume_sle(y_max);
    }

    // x <= y means y >= x_min, but only if that doesn't exceed y_max
    if x_min <= y_smax {
        state.get_bounds_mut(y).assume_sge(x_min);
    }
}

/// Assumes x >= y
pub fn assume_ge(state: &mut IntervalState, x: Reg, y: Reg) {
    assume_le(state, y, x);
}

/// Assumes x > y
pub fn assume_gt(state: &mut IntervalState, x: Reg, y: Reg) {
    let y_max = state.get_bounds(y).smax;
    let x_min = state.get_bounds(x).smin;
    let x_max = state.get_bounds(x).smax;
    let y_min = state.get_bounds(y).smin;

    // Only apply constraints if they won't create inconsistent bounds
    // x > y means x >= y_max + 1, but only if that doesn't exceed x_max
    if y_max != i64::MAX {
        let new_x_min = y_max.saturating_add(1);
        if new_x_min <= x_max {
            state.get_bounds_mut(x).assume_sge(new_x_min);
        }
    }

    // x > y means y <= x_min - 1, but only if that doesn't go below y_min
    if x_min != i64::MIN {
        let new_y_max = x_min.saturating_sub(1);
        if new_y_max >= y_min {
            state.get_bounds_mut(y).assume_sle(new_y_max);
        }
    }
}

/// Assumes x <= y + c (not directly expressible without relational info)
/// We approximate by: x <= max(y) + c
pub fn assume_le_offset(state: &mut IntervalState, x: Reg, y: Reg, c: i64) {
    let y_max = state.get_bounds(y).smax;
    if y_max != i64::MAX {
        state.get_bounds_mut(x).assume_sle(y_max.saturating_add(c));
    }
}

/// Assumes x <= c
pub fn assume_le_imm(state: &mut IntervalState, x: Reg, c: i64) {
    state.get_bounds_mut(x).assume_sle(c);
}

/// Assumes x >= c
pub fn assume_ge_imm(state: &mut IntervalState, x: Reg, c: i64) {
    state.get_bounds_mut(x).assume_sge(c);
}

/// Assumes min <= x <= max
pub fn assume_range(state: &mut IntervalState, x: Reg, min: i64, max: i64) {
    assume_ge_imm(state, x, min);
    assume_le_imm(state, x, max);
}

/// Assumes x == c
pub fn assume_eq_imm(state: &mut IntervalState, x: Reg, c: i64) {
    if x != Reg::Zero && !x.is_anchor() {
        // Preserve pointer offset if it's consistent with the constant
        let ptr_offset = state.get_ptr_offset(x).cloned();
        state.set(
            x,
            RegInterval {
                bounds: ScalarBounds::constant(c),
                ptr_offset,
            },
        );
    }
}

/// Assumes x < c
pub fn assume_lt_imm(state: &mut IntervalState, x: Reg, c: i64) {
    if c != i64::MIN {
        state.get_bounds_mut(x).assume_sle(c - 1);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Packet Geometry
// ══════════════════════════════════════════════════════════════════════════════

/// Establishes the invariant: data_meta <= data <= data_end
pub fn init_packet_anchors(state: &mut IntervalState) {
    // Set up anchor registers with their identity offsets
    state.set(
        Reg::AnchorDataMeta,
        RegInterval::with_ptr_offset(
            ScalarBounds::unknown(),
            PtrOffset::at_anchor(Reg::AnchorDataMeta),
        ),
    );
    state.set(
        Reg::AnchorData,
        RegInterval::with_ptr_offset(
            ScalarBounds::unknown(),
            PtrOffset::at_anchor(Reg::AnchorData),
        ),
    );
    state.set(
        Reg::AnchorDataEnd,
        RegInterval::with_ptr_offset(
            ScalarBounds::unknown(),
            PtrOffset::at_anchor(Reg::AnchorDataEnd),
        ),
    );
    // Note: The ordering data_meta <= data <= data_end is implicit
    // and will be used during bounds checking
}

/// Binds a register to a packet anchor (reg == anchor)
pub fn bind_to_anchor(state: &mut IntervalState, reg: Reg, anchor: Reg) {
    if !anchor.is_anchor() {
        return;
    }

    state.set(
        reg,
        RegInterval::with_ptr_offset(
            ScalarBounds::unknown(), // Value unknown, but offset is known
            PtrOffset::at_anchor(anchor),
        ),
    );
}

/// Check if a memory access [off, off + size) is within [anchor_start, anchor_end]
/// Returns (start_safe, end_safe)
pub fn check_region_access(
    state: &IntervalState,
    base: Reg,
    off: i64,
    size: i64,
    anchor_start: Reg,
    anchor_end: Reg,
) -> (bool, bool) {
    let base_offset = state.get_ptr_offset(base);

    match base_offset {
        Some(po) if po.anchor == anchor_start => {
            // Base is relative to anchor_start
            // start_safe: base >= anchor_start, i.e., offset >= 0
            let min_off = po.min_offset().saturating_add(off);
            let start_safe = min_off >= 0;

            // end_safe: base + off + size <= anchor_end
            //
            // Method 1: Use per-register proven range (works for variable offsets too)
            // If po.range is set, then we know from base we can access range bytes.
            // Access is safe if: off + size <= range
            let end_safe_by_range = if let Some(range) = po.range {
                off.saturating_add(size) <= range
            } else {
                false
            };

            // Method 2: Use global packet/meta size bounds
            // DISABLED: The kernel only uses per-register range, not global bounds.
            // Using global bounds causes soundness issues when a subprog's pointer
            // in the stack is accessed using the caller's global bound.
            let end_safe_by_global = false;
            let _ = anchor_end; // suppress unused warning

            let end_safe = end_safe_by_range || end_safe_by_global;

            (start_safe, end_safe)
        }
        _ => {
            // Cannot determine relationship
            (false, false)
        }
    }
}

/// Convenience check for the packet metadata region [data_meta, data)
pub fn verify_packet_meta_bounds(
    state: &IntervalState,
    base: Reg,
    off: i64,
    size: i64,
) -> (bool, bool) {
    check_region_access(state, base, off, size, Reg::AnchorDataMeta, Reg::AnchorData)
}

/// Convenience check for the packet region [data, data_end)
pub fn verify_packet_bounds(state: &IntervalState, base: Reg, off: i64, size: i64) -> (bool, bool) {
    check_region_access(state, base, off, size, Reg::AnchorData, Reg::AnchorDataEnd)
}

/// Re-initializes anchoring constraints to their default states
pub fn reset_packet_anchors(state: &mut IntervalState) {
    init_packet_anchors(state);
    // Clear packet size bound since we're resetting
    // Note: This might be too aggressive - consider keeping if still valid
}

/// Merges anchor-to-anchor constraints from callee to caller
/// For interval domain, we do NOT preserve global packet/meta size bounds
/// because the kernel verifier only tracks per-register range info.
/// The per-register range info for callee-saved registers is handled separately
/// in transfer_exit.
pub fn preserve_anchor_constraints(_caller: &mut IntervalState, _callee: &IntervalState) {
    // Intentionally empty for interval domain.
    // Global packet_size_lower_bound should NOT be preserved across function
    // returns because a spilled pointer in the caller stack that was never
    // bounds-checked should not benefit from the callee's bounds check.
}
