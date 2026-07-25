// Unified numeric domain abstraction
//
// This enum wraps the different numeric abstract domains (Zone, Interval)
// and provides a unified interface for the verifier.

use super::interval::IntervalState;
use super::interval::ops as interval_ops;
use super::zone::dbm::{Dbm, INF};
use super::zone::ops as zone_ops;
use crate::analysis::machine::reg::Reg;

/// Unified numeric domain that abstracts over Zone (DBM) and Interval
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum NumericDomain {
    /// Zone domain using Difference Bound Matrix
    /// Tracks relational constraints: x - y <= c
    Zone(Dbm),

    /// Interval domain (kernel verifier style)
    /// Tracks per-register bounds only
    Interval(IntervalState),
}

impl NumericDomain {
    // ══════════════════════════════════════════════════════════════════════════
    //  Constructors
    // ══════════════════════════════════════════════════════════════════════════

    /// Create a new Zone domain
    pub fn new_zone() -> Self {
        NumericDomain::Zone(Dbm::new())
    }

    /// Create a new Interval domain
    pub fn new_interval() -> Self {
        NumericDomain::Interval(IntervalState::new())
    }

    /// Check if this is an Interval domain
    pub fn is_interval_mode(&self) -> bool {
        matches!(self, NumericDomain::Interval(_))
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Query & Interval Analysis
    // ══════════════════════════════════════════════════════════════════════════

    /// Extracts the interval [lower_bound, upper_bound] for a register
    pub fn get_interval(&self, x: Reg) -> (i64, i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::get_interval(dbm, x),
            NumericDomain::Interval(ivl) => interval_ops::get_interval(ivl, x),
        }
    }

    /// Returns the interval of the distance between two registers: [lo, hi] where lo <= x - y <= hi
    pub fn get_distance_interval(&self, x: Reg, y: Reg) -> (i64, i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::get_distance_interval(dbm, x, y),
            NumericDomain::Interval(ivl) => interval_ops::get_distance_interval(ivl, x, y),
        }
    }

    /// Extacts the 32-bit signed bounds for a register
    pub fn get_s32_bounds(&self, x: Reg) -> (i32, i32) {
        match self {
            NumericDomain::Zone(dbm) => {
                let b = &dbm.bounds[x.idx()];
                (b.s32_min, b.s32_max)
            }
            NumericDomain::Interval(ivl) => {
                let st = ivl.get_bounds(x);
                // 64-bit-derived s32 bound (original behavior), then intersect
                // with the dedicated s32 fields so W32 signed branch narrowing
                // (kept by `sync_bounds`) is honored. Intersection ⇒ never
                // looser than the derived bound.
                let derived = if st.smin >= i32::MIN as i64 && st.smax <= i32::MAX as i64 {
                    (st.smin as i32, st.smax as i32)
                } else if st.smin >= 0 && st.smax <= u32::MAX as i64 {
                    // A zero-extended 32-bit value (e.g. `w0 = -EPERM` lowers
                    // to a W32 mov of 0xFFFFFFFF → u64 4294967295). The kernel
                    // `retval_range_s32` (and 32-bit ALU bounds) interpret the
                    // low 32 bits as SIGNED, so 0xFFFFFFFF reads as -1, not a
                    // huge positive. Reinterpret — but only when the u32 range
                    // does not straddle the sign boundary 0x80000000, where the
                    // s32 view wraps and is not a contiguous interval. Without
                    // this, LSM int-hooks returning `-EPERM` FALSE-REJECT
                    // ("Invalid return code", expected range [-4095, 0]).
                    let lo = st.smin as u32 as i32;
                    let hi = st.smax as u32 as i32;
                    if lo <= hi {
                        (lo, hi)
                    } else {
                        (i32::MIN, i32::MAX)
                    }
                } else {
                    (i32::MIN, i32::MAX)
                };
                let lo = derived.0.max(st.s32_min);
                let hi = derived.1.min(st.s32_max);
                if lo <= hi { (lo, hi) } else { derived }
            }
        }
    }

    /// Returns the exact distance between two registers if constant
    pub fn get_distance_fixed(&self, x: Reg, y: Reg) -> Option<i64> {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::get_distance_fixed(dbm, x, y),
            NumericDomain::Interval(ivl) => interval_ops::get_distance_fixed(ivl, x, y),
        }
    }

    /// Returns the fixed concrete value of a register if constant
    pub fn get_fixed_value(&self, x: Reg) -> Option<i64> {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::get_fixed_value(dbm, x),
            NumericDomain::Interval(ivl) => interval_ops::get_fixed_value(ivl, x),
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Predicates & Proofs
    // ══════════════════════════════════════════════════════════════════════════

    /// Returns true if the register is proven to be exactly zero
    pub fn proven_zero(&self, x: Reg) -> bool {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::proven_zero(dbm, x),
            NumericDomain::Interval(ivl) => interval_ops::proven_zero(ivl, x),
        }
    }

    /// Returns true if the register is proven to be >= 0
    pub fn proven_nonnegative(&self, x: Reg) -> bool {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::proven_nonnegative(dbm, x),
            NumericDomain::Interval(ivl) => interval_ops::proven_nonnegative(ivl, x),
        }
    }

    /// Returns true if the register is proven to be > 0
    pub fn proven_positive(&self, x: Reg) -> bool {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::proven_positive(dbm, x),
            NumericDomain::Interval(ivl) => interval_ops::proven_positive(ivl, x),
        }
    }

    /// Returns true if a register is proven to be in the u32 range [0, 2^32-1]
    pub fn proven_u32_range(&self, v: Reg, _zero: Reg) -> bool {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::proven_u32_range(dbm, v, Reg::Zero),
            NumericDomain::Interval(ivl) => interval_ops::proven_u32_range(ivl, v),
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Value Assignments
    // ══════════════════════════════════════════════════════════════════════════

    /// Removes all constraints related to the specified register
    pub fn forget(&mut self, x: Reg) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::forget(dbm, x),
            NumericDomain::Interval(ivl) => interval_ops::forget(ivl, x),
        }
    }

    /// Overwrites a register with a specific constant value
    #[allow(dead_code)]
    pub fn assign_imm(&mut self, x: Reg, imm: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::assign_imm(dbm, x, imm),
            NumericDomain::Interval(ivl) => interval_ops::assign_imm(ivl, x, imm),
        }
    }

    /// Overwrites a register with the value of another register
    pub fn assign_reg(&mut self, x: Reg, y: Reg) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::assign_reg(dbm, x, y),
            NumericDomain::Interval(ivl) => interval_ops::assign_reg(ivl, x, y),
        }
    }

    /// Intersect `x`'s range with `y`'s (constraint form of `x == y`).
    /// Preserves prior constraints on `x` so the caller can detect a
    /// contradiction via `is_inconsistent` when the equality is
    /// infeasible. Used by `if x == y` branch refinement (zone domain).
    pub fn intersect_eq_reg(&mut self, x: Reg, y: Reg) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::intersect_eq_reg(dbm, x, y),
            // Interval domain: intersect bounds element-wise. If the
            // resulting interval is empty `is_inconsistent` will report it.
            NumericDomain::Interval(ivl) => interval_ops::intersect_eq_reg(ivl, x, y),
        }
    }

    /// Restore the unsigned view of a register to full range, for
    /// mixed-sign cases where the signed narrowing
    /// (e.g. helper-return `[-MAX_ERRNO, msize]`) silently corrupted
    /// umax via cross-propagation in `assume_sle`. The unsigned
    /// representation of a mixed-sign signed range is two disjoint
    /// pieces `[0, smax] ∪ [smin as u64, u64::MAX]` and can't be
    /// represented by a single contiguous unsigned interval; the
    /// kernel-faithful answer is `[0, u64::MAX]`. Re-runs sync_bounds
    /// so the 32-bit halves get re-derived correctly without the
    /// stale narrowed umax dragging s32_min to 0 (sync_bounds path 1).
    pub fn restore_full_unsigned_range(&mut self, x: Reg) {
        match self {
            NumericDomain::Zone(_) => {
                // Zone domain doesn't track umin/umax explicitly;
                // its DBM bounds are inherently signed. Nothing to
                // restore.
            }
            NumericDomain::Interval(ivl) => {
                let b = ivl.get_bounds_mut(x);
                b.umin = 0;
                b.umax = u64::MAX;
                b.u32_min = 0;
                b.u32_max = u32::MAX;
                // Reset 32-bit signed to full range too so sync_bounds
                // re-derives them from the (now correct) 64-bit signed
                // interval without retaining the bogus s32_min=0 set
                // earlier by the path-1 propagation.
                b.s32_min = i32::MIN;
                b.s32_max = i32::MAX;
                b.sync_bounds();
            }
        }
    }

    /// Explicitly sets the 32-bit signed bounds for a register
    pub fn set_s32_bounds(&mut self, x: Reg, min: i32, max: i32) {
        match self {
            NumericDomain::Zone(dbm) => {
                dbm.bounds[x.idx()].s32_min = min;
                dbm.bounds[x.idx()].s32_max = max;
                zone_ops::sync_bounds(dbm, x);
            }
            NumericDomain::Interval(ivl) => {
                if x == Reg::Zero || x.is_anchor() {
                    return;
                }
                let b = ivl.get_bounds_mut(x);
                b.s32_min = b.s32_min.max(min);
                b.s32_max = b.s32_max.min(max);
                b.sync_bounds();
            }
        }
    }

    /// Extracts the 64-bit unsigned bounds (kernel `umin_value` /
    /// `umax_value`) for a register. These are tracked INDEPENDENTLY of
    /// the signed interval — a value can have `umax=0xffffffff` while
    /// `smax=0x7fffffff` (e.g. a zero-extended 32-bit jump-table index).
    /// `bcf_bound_reg` emits both as separate predicates, so the BCF
    /// materializer needs the real u64 bounds rather than a smax-derived
    /// approximation.
    pub fn get_u64_bounds(&self, x: Reg) -> (u64, u64) {
        match self {
            NumericDomain::Zone(dbm) => {
                let b = &dbm.bounds[x.idx()];
                (b.u64_min, b.u64_max)
            }
            NumericDomain::Interval(ivl) => {
                let st = ivl.get_bounds(x);
                (st.umin, st.umax)
            }
        }
    }

    /// Extracts the 32-bit unsigned bounds for a register.
    pub fn get_u32_bounds(&self, x: Reg) -> (u32, u32) {
        match self {
            NumericDomain::Zone(dbm) => {
                let b = &dbm.bounds[x.idx()];
                (b.u32_min, b.u32_max)
            }
            NumericDomain::Interval(ivl) => {
                let st = ivl.get_bounds(x);
                // 64-bit-derived u32 bound (the original behavior — sound
                // whenever the upper 32 bits are constant).
                let (d_lo, d_hi) = if st.umax <= u32::MAX as u64 {
                    (st.umin as u32, st.umax as u32)
                } else {
                    (0, u32::MAX)
                };
                // Intersect with the dedicated 32-bit fields (kernel
                // `u32_{min,max}_value`, kept consistent by `sync_bounds`).
                // These carry W32 branch narrowing the 64-bit range can't
                // represent (the low 32 bits the branch constrains while the
                // upper bits stay unknown). Intersection ⇒ never looser than
                // the old derived bound, so no precision regression; the
                // dedicated tightening closes the W32 deduction FRs.
                let lo = d_lo.max(st.u32_min);
                let hi = d_hi.min(st.u32_max);
                if lo <= hi { (lo, hi) } else { (d_lo, d_hi) }
            }
        }
    }

    /// Explicitly sets the 32-bit unsigned bounds for a register, used by
    /// `apply_w32_unsigned_fallback` to record W32 branch narrowing.
    pub fn set_u32_bounds(&mut self, x: Reg, min: u32, max: u32) {
        match self {
            NumericDomain::Zone(dbm) => {
                dbm.bounds[x.idx()].u32_min = min;
                dbm.bounds[x.idx()].u32_max = max;
                zone_ops::sync_bounds(dbm, x);
            }
            NumericDomain::Interval(ivl) => {
                if x == Reg::Zero || x.is_anchor() {
                    return;
                }
                let b = ivl.get_bounds_mut(x);
                // Intersect (narrowing only) then re-sync so the W32 range
                // propagates into s32 / back to the 64-bit halves where the
                // upper bits are known.
                b.u32_min = b.u32_min.max(min);
                b.u32_max = b.u32_max.min(max);
                b.sync_bounds();
            }
        }
    }

    /// Explicitly narrows the 64-bit unsigned bounds for a register
    /// (kernel `umin_value`/`umax_value`). Intersect-only, then re-sync,
    /// mirroring `set_u32_bounds`. Used by the branch `!=` edge-bump
    /// (kernel `regs_refine_cond_op` BPF_JNE, verifier.c:17124) — the
    /// signed interval cannot carry `umin=1` for a full-range scalar
    /// (smin stays S64_MIN), so the fact must live in the u64 pair.
    pub fn set_u64_bounds(&mut self, x: Reg, min: u64, max: u64) {
        match self {
            NumericDomain::Zone(dbm) => {
                let b = &mut dbm.bounds[x.idx()];
                b.u64_min = b.u64_min.max(min);
                b.u64_max = b.u64_max.min(max);
                zone_ops::sync_bounds(dbm, x);
            }
            NumericDomain::Interval(ivl) => {
                if x == Reg::Zero || x.is_anchor() {
                    return;
                }
                let b = ivl.get_bounds_mut(x);
                b.umin = b.umin.max(min);
                b.umax = b.umax.min(max);
                b.sync_bounds();
            }
        }
    }

    /// Establishes the relationship dst = src + imm
    pub fn assign_reg_offset(&mut self, dst: Reg, src: Reg, imm: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::assign_reg_offset(dbm, dst, src, imm),
            NumericDomain::Interval(ivl) => interval_ops::assign_reg_offset(ivl, dst, src, imm),
        }
    }

    /// Assigns a concrete interval to a register
    pub fn assign_interval(&mut self, r: Reg, min: i64, max: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::assign_interval(dbm, r, min, max),
            NumericDomain::Interval(ivl) => interval_ops::assign_interval(ivl, r, min, max),
        }
    }

    /// Initializes a register as a map value pointer (interval mode only)
    /// Sets up PtrOffset tracking for bounds checking
    pub fn init_map_value_ptr(&mut self, reg: Reg) {
        if let NumericDomain::Interval(ivl) = self {
            interval_ops::init_map_value_ptr(ivl, reg);
        }
        // Zone domain doesn't need special setup - it tracks via DBM constraints
    }

    /// Like `init_map_value_ptr` but seeds the map-value pointer at a fixed
    /// non-zero `offset` from the value start (a direct LD_IMM64
    /// BPF_PSEUDO_MAP_VALUE / .bss/.data/.rodata global lives at its
    /// section offset). Interval mode seeds the PtrOffset so a later
    /// bounded-variable index folds into a checkable offset range; Zone mode
    /// preserves the prior `forget` behavior (it tracks offsets via DBM
    /// constraints anchored elsewhere).
    pub fn init_map_value_ptr_at(&mut self, reg: Reg, offset: i64) {
        match self {
            NumericDomain::Interval(ivl) => interval_ops::init_map_value_ptr_at(ivl, reg, offset),
            _ => self.forget(reg),
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Arithmetic Transformations
    // ══════════════════════════════════════════════════════════════════════════

    /// Performs dst += imm
    pub fn apply_add_imm(&mut self, dst: Reg, imm: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::apply_add_imm(dbm, dst, imm),
            NumericDomain::Interval(ivl) => interval_ops::apply_add_imm(ivl, dst, imm),
        }
    }

    /// Performs dst -= imm. Interval mode mirrors kernel
    /// `scalar_min_max_sub` with a known src (NOT equivalent to adding
    /// the negation — see `interval_ops::apply_sub_imm`). Zone mode keeps
    /// its relational add-of-negation, which is exact over signed DBM.
    pub fn apply_sub_imm(&mut self, dst: Reg, imm: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::apply_add_imm(dbm, dst, -imm),
            NumericDomain::Interval(ivl) => interval_ops::apply_sub_imm(ivl, dst, imm),
        }
    }

    /// Performs dst += src
    pub fn apply_add_reg(&mut self, dst: Reg, src: Reg) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::apply_add_reg(dbm, dst, src),
            NumericDomain::Interval(ivl) => interval_ops::apply_add_reg(ivl, dst, src),
        }
    }

    /// Performs dst = scalar_dst + ptr_src (interval mode only)
    /// Creates a new PtrOffset for dst combining ptr's offset with scalar's range
    pub fn apply_scalar_add_ptr(&mut self, dst: Reg, ptr_src: Reg, scalar_lo: i64, scalar_hi: i64) {
        if let NumericDomain::Interval(ivl) = self {
            interval_ops::apply_scalar_add_ptr(ivl, dst, ptr_src, scalar_lo, scalar_hi);
        }
        // Zone domain handles this via constraints, no special action needed
    }

    /// Performs dst -= src
    pub fn apply_sub_reg(&mut self, dst: Reg, src: Reg) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::apply_sub_reg(dbm, dst, src),
            NumericDomain::Interval(ivl) => interval_ops::apply_sub_reg(ivl, dst, src),
        }
    }

    /// Performs dst &= mask
    pub fn apply_and_imm(&mut self, dst: Reg, mask: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::apply_and_imm(dbm, dst, mask),
            NumericDomain::Interval(ivl) => interval_ops::apply_and_imm(ivl, dst, mask),
        }
    }

    /// Performs dst *= imm
    pub fn apply_mul_imm(&mut self, dst: Reg, imm: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::apply_mul_imm(dbm, dst, imm),
            NumericDomain::Interval(ivl) => interval_ops::apply_mul_imm(ivl, dst, imm),
        }
    }

    /// Performs dst /= imm
    pub fn apply_div_imm(&mut self, reg: Reg, imm: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::apply_div_imm(dbm, reg, imm),
            NumericDomain::Interval(ivl) => interval_ops::apply_div_imm(ivl, reg, imm),
        }
    }

    /// Performs dst /= src (conservative: forgets destination)
    pub fn apply_div_reg(&mut self, dst: Reg, _src: Reg) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::apply_div_reg(dbm, dst, _src),
            NumericDomain::Interval(ivl) => interval_ops::apply_div_reg(ivl, dst),
        }
    }

    /// Performs reg = -reg
    pub fn apply_neg(&mut self, reg: Reg) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::apply_neg(dbm, reg),
            NumericDomain::Interval(ivl) => interval_ops::apply_neg(ivl, reg),
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Constraint Refinement (Branch conditions)
    // ══════════════════════════════════════════════════════════════════════════

    /// Assumes x <= y
    pub fn assume_le(&mut self, x: Reg, y: Reg) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::assume_le(dbm, x, y),
            NumericDomain::Interval(ivl) => interval_ops::assume_le(ivl, x, y),
        }
    }

    /// Assumes x >= y
    pub fn assume_ge(&mut self, x: Reg, y: Reg) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::assume_ge(dbm, x, y),
            NumericDomain::Interval(ivl) => interval_ops::assume_ge(ivl, x, y),
        }
    }

    /// Assumes x > y
    pub fn assume_gt(&mut self, x: Reg, y: Reg) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::assume_gt(dbm, x, y),
            NumericDomain::Interval(ivl) => interval_ops::assume_gt(ivl, x, y),
        }
    }

    /// Assumes x <= y + c
    pub fn assume_le_offset(&mut self, x: Reg, y: Reg, c: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::assume_le_offset(dbm, x, y, c),
            NumericDomain::Interval(ivl) => interval_ops::assume_le_offset(ivl, x, y, c),
        }
    }

    /// Assumes x <= c
    pub fn assume_le_imm(&mut self, x: Reg, c: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::assume_le_imm(dbm, x, c),
            NumericDomain::Interval(ivl) => interval_ops::assume_le_imm(ivl, x, c),
        }
    }

    /// Assumes x >= c
    pub fn assume_ge_imm(&mut self, x: Reg, c: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::assume_ge_imm(dbm, x, c),
            NumericDomain::Interval(ivl) => interval_ops::assume_ge_imm(ivl, x, c),
        }
    }

    /// Assumes min <= x <= max
    pub fn assume_range(&mut self, x: Reg, min: i64, max: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::assume_range(dbm, x, min, max),
            NumericDomain::Interval(ivl) => interval_ops::assume_range(ivl, x, min, max),
        }
    }

    /// Assumes x == c
    pub fn assume_eq_imm(&mut self, x: Reg, c: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::assume_eq_imm(dbm, x, c),
            NumericDomain::Interval(ivl) => interval_ops::assume_eq_imm(ivl, x, c),
        }
    }

    /// Assumes x < c
    pub fn assume_lt_imm(&mut self, x: Reg, c: i64) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::assume_lt_imm(dbm, x, c),
            NumericDomain::Interval(ivl) => interval_ops::assume_lt_imm(ivl, x, c),
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Width Truncation
    // ══════════════════════════════════════════════════════════════════════════

    /// Apply W32 truncation to a register's bounds.
    /// If the current bounds exceed [0, 0xFFFFFFFF], widen to that range.
    pub fn apply_w32_truncation(&mut self, dst: Reg) {
        let (lo, hi) = self.get_interval(dst);
        let safe = lo >= 0 && hi <= 0xFFFFFFFF;

        if !safe {
            // Check if the lower 32 bits form a non-wrapping range.
            let tight = if lo != i64::MIN && hi != i64::MAX {
                let l_u = lo as u64;
                let h_u = hi as u64;
                (l_u >> 32) == (h_u >> 32)
            } else {
                false
            };

            if tight {
                let new_lo = (lo as u64 & 0xFFFFFFFF) as i64;
                let new_hi = (hi as u64 & 0xFFFFFFFF) as i64;
                self.forget(dst);
                self.assume_ge_imm(dst, new_lo);
                self.assume_le_imm(dst, new_hi);
            } else {
                self.forget(dst);
                self.assume_ge_imm(dst, 0);
                self.assume_le_imm(dst, 0xFFFFFFFF);
            }
        }
    }

    /// Kernel `zext_32_to_64` (verifier.c): after a 32-bit ALU op the
    /// destination is zero-extended, so its 64-bit bounds equal its 32-bit
    /// bounds. Mirrors `__reg_assign_32_into_64`. Applied uniformly at the
    /// W32 ALU tail so umax/smax reflect the zero-extension (the kernel
    /// does this for every BPF_ALU 32-bit-class op).
    pub fn zext_32_into_64(&mut self, x: Reg) {
        if x == Reg::Zero || x.is_anchor() {
            return;
        }
        match self {
            NumericDomain::Zone(dbm) => {
                let b = &mut dbm.bounds[x.idx()];
                b.u64_min = b.u32_min as u64;
                b.u64_max = b.u32_max as u64;
                if b.s32_min >= 0 && b.s32_max >= 0 {
                    b.s64_min = b.s32_min as i64;
                    b.s64_max = b.s32_max as i64;
                } else {
                    b.s64_min = 0;
                    b.s64_max = u32::MAX as i64;
                }
                zone_ops::sync_bounds(dbm, x);
            }
            NumericDomain::Interval(ivl) => {
                ivl.get_bounds_mut(x).assign_32_into_64();
            }
        }
    }

    /// Check if value is known to be in u32 range [0, 0xFFFFFFFF]
    pub fn fits_in_u32_range(&self, reg: Reg) -> bool {
        let (lo, hi) = self.get_interval(reg);
        if lo != i64::MIN && hi != i64::MAX {
            lo >= 0 && hi <= 0xFFFFFFFF
        } else {
            false
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Packet Geometry
    // ══════════════════════════════════════════════════════════════════════════

    /// Establishes the invariant: data_meta <= data <= data_end
    pub fn init_packet_anchors(&mut self) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::init_packet_anchors(dbm),
            NumericDomain::Interval(ivl) => interval_ops::init_packet_anchors(ivl),
        }
    }

    /// Binds a register to a packet anchor (reg == anchor)
    pub fn bind_to_anchor(&mut self, reg: Reg, anchor: Reg) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::bind_to_anchor(dbm, reg, anchor),
            NumericDomain::Interval(ivl) => interval_ops::bind_to_anchor(ivl, reg, anchor),
        }
    }

    /// Check if a memory access [off, off + size) is within [anchor_start, anchor_end]
    #[allow(dead_code)]
    pub fn check_region_access(
        &self,
        base: Reg,
        off: i64,
        size: i64,
        anchor_start: Reg,
        anchor_end: Reg,
    ) -> (bool, bool) {
        match self {
            NumericDomain::Zone(dbm) => {
                zone_ops::check_region_access(dbm, base, off, size, anchor_start, anchor_end)
            }
            NumericDomain::Interval(ivl) => {
                interval_ops::check_region_access(ivl, base, off, size, anchor_start, anchor_end)
            }
        }
    }

    /// Check for the packet metadata region [data_meta, data)
    pub fn verify_packet_meta_bounds(&self, base: Reg, off: i64, size: i64) -> (bool, bool) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::verify_packet_meta_bounds(dbm, base, off, size),
            NumericDomain::Interval(ivl) => {
                interval_ops::verify_packet_meta_bounds(ivl, base, off, size)
            }
        }
    }

    /// Check for the packet region [data, data_end)
    pub fn verify_packet_bounds(&self, base: Reg, off: i64, size: i64) -> (bool, bool) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::verify_packet_bounds(dbm, base, off, size),
            NumericDomain::Interval(ivl) => {
                interval_ops::verify_packet_bounds(ivl, base, off, size)
            }
        }
    }

    /// Re-initializes anchoring constraints to their default states
    pub fn reset_packet_anchors(&mut self) {
        match self {
            NumericDomain::Zone(dbm) => zone_ops::reset_packet_anchors(dbm),
            NumericDomain::Interval(ivl) => interval_ops::reset_packet_anchors(ivl),
        }
    }

    /// Clear packet and meta size bounds (interval mode only).
    /// Called when entering a function to match kernel behavior where each
    /// function tracks its own bounds independently.
    pub fn clear_packet_size_bounds(&mut self) {
        if let NumericDomain::Interval(ivl) = self {
            ivl.clear_packet_size_bounds();
        }
        // Zone mode doesn't have global packet size bounds - it uses DBM constraints
    }

    /// Merges anchor-to-anchor constraints from callee to caller
    pub fn preserve_anchor_constraints(&mut self, callee: &NumericDomain) {
        match (self, callee) {
            (NumericDomain::Zone(caller_dbm), NumericDomain::Zone(callee_dbm)) => {
                zone_ops::preserve_anchor_constraints(caller_dbm, callee_dbm)
            }
            (NumericDomain::Interval(caller_ivl), NumericDomain::Interval(callee_ivl)) => {
                interval_ops::preserve_anchor_constraints(caller_ivl, callee_ivl)
            }
            _ => {
                // Mismatched domains - should not happen in practice
                panic!("Cannot preserve anchor constraints between different domain types");
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  DBM-specific operations (for compatibility during migration)
    // ══════════════════════════════════════════════════════════════════════════

    /// Returns true if the domain is inconsistent (infeasible state)
    pub fn is_inconsistent(&self) -> bool {
        match self {
            NumericDomain::Zone(dbm) => dbm.is_inconsistent(),
            NumericDomain::Interval(ivl) => ivl.is_inconsistent(),
        }
    }

    /// Close the domain (compute transitive closure for Zone)
    pub fn close(&mut self) {
        match self {
            NumericDomain::Zone(dbm) => dbm.close(),
            NumericDomain::Interval(_ivl) => {
                // Interval domain doesn't need closure
            }
        }
    }

    /// Activates provenance tracking for PCC certificate generation (Zone only).
    #[allow(dead_code)]
    pub fn enable_provenance(&mut self) {
        if let NumericDomain::Zone(dbm) = self {
            dbm.enable_provenance();
        }
    }

    /// Sets the current program counter for provenance attribution (Zone only).
    #[inline]
    pub fn set_current_pc(&mut self, pc: usize) {
        if let NumericDomain::Zone(dbm) = self {
            dbm.set_current_pc(pc);
        }
    }

    /// Add a raw constraint i - j <= c (Zone-specific)
    pub fn add_constraint(&mut self, i: Reg, j: Reg, c: i64) {
        match self {
            NumericDomain::Zone(dbm) => {
                dbm.add_constraint(i, j, c);
            }
            NumericDomain::Interval(ivl) => {
                // Interval domain: convert relational constraint to bounds if possible
                // For i - Zero <= c: i <= c (upper bound on i)
                // For Zero - i <= c: i >= -c (lower bound on i)
                if j == Reg::Zero {
                    interval_ops::assume_le_imm(ivl, i, c);
                } else if i == Reg::Zero {
                    interval_ops::assume_ge_imm(ivl, j, -c);
                }
                // Other relational constraints cannot be expressed in interval domain
            }
        }
    }

    /// Get raw constraint value (Zone-specific)
    pub fn get(&self, i: Reg, j: Reg) -> i64 {
        match self {
            NumericDomain::Zone(dbm) => dbm.get(i, j),
            NumericDomain::Interval(_ivl) => {
                // Return INF (no constraint) for interval domain
                INF
            }
        }
    }

    /// Set raw constraint value (Zone-specific)
    #[allow(dead_code)]
    pub fn set(&mut self, i: Reg, j: Reg, val: i64) {
        match self {
            NumericDomain::Zone(dbm) => dbm.set(i, j, val),
            NumericDomain::Interval(_ivl) => {
                // Interval domain: no-op for relational constraints
            }
        }
    }

    /// Widen for loop convergence (Zone-specific, interval doesn't need it)
    #[allow(dead_code)]
    pub fn widen(&self, newer: &NumericDomain) -> NumericDomain {
        match (self, newer) {
            (NumericDomain::Zone(old), NumericDomain::Zone(new)) => {
                NumericDomain::Zone(old.widen(new))
            }
            (NumericDomain::Interval(_), NumericDomain::Interval(new_ivl)) => {
                // Interval domain: no widening, preserve the newer state
                // (widening would corrupt the state by replacing it with old values)
                NumericDomain::Interval(new_ivl.clone())
            }
            _ => panic!("Cannot widen between different domain types"),
        }
    }

    /// Returns a compact string of non-trivial relational constraints for log lines.
    ///
    /// - Zone mode: pairwise DBM constraints, e.g. `r2-r10==-8  r4-@data in [0,100]`
    /// - Interval mode: global packet / meta geometry, e.g. `pkt>=100  meta<20`
    ///
    /// Returns an empty string when there is nothing worth logging.
    pub fn relations_str(&self) -> String {
        match self {
            NumericDomain::Zone(dbm) => dbm.relations_str(),
            NumericDomain::Interval(ivl) => ivl.global_constraints_str(),
        }
    }

    /// Returns the PtrOffset of a register formatted as `@anchor[±off][+[lo,hi]]`,
    /// or `None` if the register has no PtrOffset (Zone mode always returns `None`).
    ///
    /// Used by `State::reg_ranges_str()` to show stack / packet pointer relationships
    /// in Interval mode, where scalar bounds are uninformative for pointer registers
    /// (e.g. R10 is `[-inf,inf]` as a scalar but carries `PtrOffset{anchor:R10,off:0}`).
    ///
    /// Format rules:
    ///   `@r10`            off=0, var_off=0
    ///   `@r10-8`          off=-8, var_off=0
    ///   `@data+[0,100]`   off=0, var_off=100  (variable offset shown as range)
    ///   `@data+[-8,0]`    off=-8, var_off=8
    pub fn ptr_offset_str(&self, r: Reg) -> Option<String> {
        let NumericDomain::Interval(ivl) = self else {
            return None;
        };
        let p = ivl.get_ptr_offset(r)?;

        // Anchor registers (AnchorData etc.) already embed "@" in their name();
        // real registers like R10 used as anchors need it added.
        let base = if p.anchor.is_anchor() {
            p.anchor.name().to_string()
        } else {
            format!("@{}", p.anchor.name())
        };

        let s = if p.var_off == 0 {
            if p.off == 0 {
                base
            } else {
                // {:+} always prints the sign, giving "@r10-8" or "@data+4"
                format!("{}{:+}", base, p.off)
            }
        } else {
            let min = p.off;
            let max = p.off.saturating_add(p.var_off as i64);
            format!("{}+[{},{}]", base, min, max)
        };
        Some(s)
    }

    /// Returns the full DBM matrix as a formatted string for deep debugging (verbosity ≥ 3).
    /// Includes all registers and anchor variables.
    /// The caller is responsible for logging the result at the desired level.
    /// Returns an empty string in Interval mode (no matrix to show).
    pub fn matrix_full_str(&self) -> String {
        match self {
            NumericDomain::Zone(dbm) => dbm.matrix_full_str(),
            NumericDomain::Interval(_ivl) => String::new(),
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Direct DBM access (for code that needs Zone-specific features)
    // ══════════════════════════════════════════════════════════════════════════

    /// Get reference to underlying Dbm if this is a Zone domain
    #[allow(dead_code)]
    pub fn as_zone(&self) -> Option<&Dbm> {
        match self {
            NumericDomain::Zone(dbm) => Some(dbm),
            NumericDomain::Interval(_) => None,
        }
    }

    /// Get mutable reference to underlying Dbm if this is a Zone domain
    #[allow(dead_code)]
    pub fn as_zone_mut(&mut self) -> Option<&mut Dbm> {
        match self {
            NumericDomain::Zone(dbm) => Some(dbm),
            NumericDomain::Interval(_) => None,
        }
    }

    /// Get reference to underlying IntervalState if this is an Interval domain
    #[allow(dead_code)]
    pub fn as_interval(&self) -> Option<&IntervalState> {
        match self {
            NumericDomain::Zone(_) => None,
            NumericDomain::Interval(ivl) => Some(ivl),
        }
    }

    /// Get mutable reference to underlying IntervalState if this is an Interval domain
    #[allow(dead_code)]
    pub fn as_interval_mut(&mut self) -> Option<&mut IntervalState> {
        match self {
            NumericDomain::Zone(_) => None,
            NumericDomain::Interval(ivl) => Some(ivl),
        }
    }

    /// Check if this is a Zone domain
    #[allow(dead_code)]
    pub fn is_zone(&self) -> bool {
        matches!(self, NumericDomain::Zone(_))
    }

    /// Check if this is an Interval domain
    #[allow(dead_code)]
    pub fn is_interval(&self) -> bool {
        matches!(self, NumericDomain::Interval(_))
    }
}

impl Default for NumericDomain {
    fn default() -> Self {
        NumericDomain::new_zone()
    }
}
