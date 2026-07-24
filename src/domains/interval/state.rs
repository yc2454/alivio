// Interval domain state representation
//
// Mirrors the kernel verifier's per-register tracking:
// - Signed and unsigned bounds (smin, smax, umin, umax)
// - Pointer offset tracking (fixed offset + variable range)
// - Scalar ID tracking for propagating bounds to copied registers

use crate::analysis::machine::reg::Reg;
use std::sync::atomic::{AtomicU32, Ordering};

/// Global counter for generating unique scalar IDs
static NEXT_SCALAR_ID: AtomicU32 = AtomicU32::new(1);

/// Generate a new unique scalar ID for tracking related scalars
pub fn new_scalar_id() -> u32 {
    NEXT_SCALAR_ID.fetch_add(1, Ordering::Relaxed)
}

/// Scalar interval bounds for a single register
/// Mirrors kernel's `bpf_reg_state` 8-bound layout: signed and
/// unsigned bounds in BOTH 64-bit and 32-bit views. The 32-bit halves
/// describe the LOW 32 bits of the value interpreted as either signed
/// or unsigned. Kernel keeps them consistent via reg_bounds_sync; in
/// zovia we initialize them conservatively (full range) and let
/// per-op transfers tighten them. range_within checks all 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarBounds {
    pub smin: i64, // Signed 64-bit minimum
    pub smax: i64, // Signed 64-bit maximum
    pub umin: u64, // Unsigned 64-bit minimum
    pub umax: u64, // Unsigned 64-bit maximum
    // Kernel `bpf_reg_state.{s32_min_value, s32_max_value,
    // u32_min_value, u32_max_value}`. Describe the LOW 32 bits of the
    // value. For a fully unknown scalar these are full type range
    // (i32::MIN..=i32::MAX, 0..=u32::MAX); a known constant pins all
    // four to its truncated 32-bit view.
    pub s32_min: i32,
    pub s32_max: i32,
    pub u32_min: u32,
    pub u32_max: u32,
    /// Scalar ID for tracking related scalars (copied registers share the same ID)
    /// When bounds are refined on one register, the refinement propagates to all
    /// registers with matching scalar_id
    pub scalar_id: Option<u32>,
}

impl ScalarBounds {
    /// Create bounds for an unknown value
    pub fn unknown() -> Self {
        ScalarBounds {
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: u64::MAX,
            s32_min: i32::MIN,
            s32_max: i32::MAX,
            u32_min: 0,
            u32_max: u32::MAX,
            scalar_id: None,
        }
    }

    /// Create bounds for a known constant
    pub fn constant(val: i64) -> Self {
        // Constants pin all 8 bounds. The 32-bit halves describe the
        // low 32 bits of the constant: re-interpret val as u64 then
        // truncate; sign view = the same low 32 bits as i32.
        let low = val as u64 as u32;
        let low_signed = low as i32;
        ScalarBounds {
            smin: val,
            smax: val,
            umin: val as u64,
            umax: val as u64,
            s32_min: low_signed,
            s32_max: low_signed,
            u32_min: low,
            u32_max: low,
            scalar_id: None, // Constants don't need tracking
        }
    }

    /// Create bounds for a non-negative value in range [0, max]
    #[allow(dead_code)]
    pub fn nonnegative(max: u64) -> Self {
        // 32-bit views: tight iff max fits in u32; otherwise stay at
        // full u32 range. Same for the signed 32 view.
        let (s32_min, s32_max, u32_min, u32_max) = if max <= u32::MAX as u64 {
            (0i32, max as i32, 0u32, max as u32)
        } else {
            (i32::MIN, i32::MAX, 0u32, u32::MAX)
        };
        ScalarBounds {
            smin: 0,
            smax: max as i64,
            umin: 0,
            umax: max,
            s32_min,
            s32_max,
            u32_min,
            u32_max,
            scalar_id: None,
        }
    }

    /// Check if this represents a constant value
    pub fn is_constant(&self) -> bool {
        self.smin == self.smax && self.umin == self.umax
    }

    /// Get the constant value if this is constant
    pub fn get_constant(&self) -> Option<i64> {
        if self.is_constant() {
            Some(self.smin)
        } else {
            None
        }
    }

    /// Check if proven >= 0
    pub fn is_nonnegative(&self) -> bool {
        self.smin >= 0
    }

    /// Check if proven > 0
    pub fn is_positive(&self) -> bool {
        self.smin > 0
    }

    /// Check if proven == 0
    pub fn is_zero(&self) -> bool {
        self.smin == 0 && self.smax == 0
    }

    /// Check if in u32 range [0, 2^32-1]
    pub fn is_u32(&self) -> bool {
        self.smin >= 0 && self.umax <= u32::MAX as u64
    }

    /// Intersect with another bounds (take tighter constraints)
    #[allow(dead_code)]
    pub fn intersect(&self, other: &ScalarBounds) -> ScalarBounds {
        ScalarBounds {
            smin: self.smin.max(other.smin),
            smax: self.smax.min(other.smax),
            umin: self.umin.max(other.umin),
            umax: self.umax.min(other.umax),
            s32_min: self.s32_min.max(other.s32_min),
            s32_max: self.s32_max.min(other.s32_max),
            u32_min: self.u32_min.max(other.u32_min),
            u32_max: self.u32_max.min(other.u32_max),
            // Preserve scalar_id if both have the same ID
            scalar_id: if self.scalar_id == other.scalar_id {
                self.scalar_id
            } else {
                None
            },
        }
    }

    /// Join with another bounds (take looser constraints)
    #[allow(dead_code)]
    pub fn join(&self, other: &ScalarBounds) -> ScalarBounds {
        ScalarBounds {
            smin: self.smin.min(other.smin),
            smax: self.smax.max(other.smax),
            umin: self.umin.min(other.umin),
            umax: self.umax.max(other.umax),
            s32_min: self.s32_min.min(other.s32_min),
            s32_max: self.s32_max.max(other.s32_max),
            u32_min: self.u32_min.min(other.u32_min),
            u32_max: self.u32_max.max(other.u32_max),
            // Preserve scalar_id if both have the same ID
            scalar_id: if self.scalar_id == other.scalar_id {
                self.scalar_id
            } else {
                None
            },
        }
    }

    /// Mirror of kernel `reg_bounds_sync` (verifier.c v6.15 L2999) —
    /// specifically the `__reg32_deduce_bounds` body (L2690). Derives
    /// tighter 32-bit bounds from the 64-bit ones when the upper 32
    /// bits are constant or sign-consistent, plus cross-syncs between
    /// signed and unsigned 32-bit views. Safe to call any time;
    /// monotonically tightens (never widens) the 32-bit fields.
    pub fn sync_bounds(&mut self) {
        // (1) u64 → u32 when upper 32 bits constant.
        if (self.umin >> 32) == (self.umax >> 32) {
            let lo_min = self.umin as u32;
            let lo_max = self.umax as u32;
            self.u32_min = self.u32_min.max(lo_min);
            self.u32_max = self.u32_max.min(lo_max);
            if (self.umin as i32) <= (self.umax as i32) {
                self.s32_min = self.s32_min.max(self.umin as i32);
                self.s32_max = self.s32_max.min(self.umax as i32);
            }
        }
        // (2) s64 → {u32, s32} when upper 32 bits constant.
        if (self.smin >> 32) == (self.smax >> 32) {
            if (self.smin as u32) <= (self.smax as u32) {
                self.u32_min = self.u32_min.max(self.smin as u32);
                self.u32_max = self.u32_max.min(self.smax as u32);
            }
            if (self.smin as i32) <= (self.smax as i32) {
                self.s32_min = self.s32_min.max(self.smin as i32);
                self.s32_max = self.s32_max.min(self.smax as i32);
            }
        }
        // (3) u32 → s32 if sign-bit consistent.
        if (self.u32_min as i32) <= (self.u32_max as i32) {
            self.s32_min = self.s32_min.max(self.u32_min as i32);
            self.s32_max = self.s32_max.min(self.u32_max as i32);
        }
        // (4) s32 → u32 if sign-bit consistent.
        if (self.s32_min as u32) <= (self.s32_max as u32) {
            self.u32_min = self.u32_min.max(self.s32_min as u32);
            self.u32_max = self.u32_max.min(self.s32_max as u32);
        }
        // (5) 32 → 64 mixed deduction (kernel `__reg_deduce_mixed_bounds`,
        // verifier.c:2955). Substitute the (now-tightest) low 32 bits into
        // the 64-bit bounds, keeping the high 32 bits from the existing
        // 64-bit range. This lets a reg whose low 32 bits are known —
        // e.g. R0 after a `w0 == 0` branch (u32=[0,0], high 32 unknown) —
        // derive umax=0xffffffff_00000000 / smax=0x7fffffff_00000000,
        // matching the bounds the kernel's bcf_bound_reg emits.
        // Always well-formed (kernel comment).
        let hi_mask: u64 = !0xffff_ffffu64;
        let new_umin = (self.umin & hi_mask) | (self.u32_min as u64);
        let new_umax = (self.umax & hi_mask) | (self.u32_max as u64);
        self.umin = self.umin.max(new_umin);
        self.umax = self.umax.min(new_umax);
        let new_smin = ((self.smin as u64 & hi_mask) | (self.u32_min as u64)) as i64;
        let new_smax = ((self.smax as u64 & hi_mask) | (self.u32_max as u64)) as i64;
        self.smin = self.smin.max(new_smin);
        self.smax = self.smax.min(new_smax);
        // (6) s64 → u64 consistency (kernel `__reg64_deduce_bounds`,
        // verifier.c:2820). A SIGN-CROSSING range [smin<0, smax>=0] can
        // take the most-negative value smin (= 0x8000.. as unsigned), so
        // its unsigned max MUST be >= 0x8000_0000_0000_0000. If a prior op
        // left umax capped below that (e.g. at i64::MAX), the reg is in
        // fact unsigned-unbounded above — the kernel keeps umax_value at
        // U64_MAX. Restoring it (a WIDENING, hence sound) stops zovia
        // emitting a spurious `ULE(v, i64::MAX)` the kernel never has.
        // Symmetrically, a fully non-negative reg's umax is its smax.
        if self.smin >= 0 {
            self.umin = self.umin.max(self.smin as u64);
            self.umax = self.umax.min(self.smax as u64);
        } else if self.smin < 0 && self.smax >= 0 && self.umax < 0x8000_0000_0000_0000 {
            self.umax = u64::MAX;
        }
    }

    /// Reset 32-bit halves to full range, then re-derive tightest
    /// possible values from the current 64-bit bounds via
    /// `sync_bounds`. Use at the end of ALU transfers that mutated
    /// the 64-bit bounds but don't have a precise 32-bit-aware path.
    /// Safer than carrying potentially-stale 32-bit halves forward
    /// when the underlying value just changed.
    pub fn forget_32_then_sync(&mut self) {
        self.s32_min = i32::MIN;
        self.s32_max = i32::MAX;
        self.u32_min = 0;
        self.u32_max = u32::MAX;
        self.sync_bounds();
    }

    /// Mirror kernel `__reg_assign_32_into_64` (verifier.c:2789) + the
    /// `zext_32_to_64` it serves: after a 32-bit ALU op the result is
    /// zero-extended, so the full 64-bit value EQUALS the 32-bit value and
    /// the 64-bit bounds must be assigned from the 32-bit ones. Without
    /// this, a register written by a W32 op keeps umax/smax at the full
    /// 64-bit range, so `bcf_bound_reg`-style materialization never emits
    /// the `ULE(reg,0xffffffff)` / signed bounds the kernel emits.
    pub fn assign_32_into_64(&mut self) {
        if std::env::var("ZOVIA_DBG_ADDIMM").ok().as_deref() == Some("1") {
            eprintln!("[a3264-in] s32=[{},{}] u32=[{:#x},{:#x}]", self.s32_min, self.s32_max, self.u32_min, self.u32_max);
        }
        self.umin = self.u32_min as u64;
        self.umax = self.u32_max as u64;
        // Pull s32 into s64 only when both halves are non-negative (the
        // value's sign-extension equals its zero-extension); otherwise the
        // zero-extended value spans [0, U32_MAX] as signed-64.
        if self.s32_min >= 0 && self.s32_max >= 0 {
            self.smin = self.s32_min as i64;
            self.smax = self.s32_max as i64;
        } else {
            self.smin = 0;
            self.smax = u32::MAX as i64;
        }
        self.sync_bounds();
    }

    /// Apply signed constraint: value <= c
    pub fn assume_sle(&mut self, c: i64) {
        self.smax = self.smax.min(c);
        if c >= 0 {
            self.umax = self.umax.min(c as u64);
        }
        self.sync_bounds();
    }

    /// Apply signed constraint: value >= c
    pub fn assume_sge(&mut self, c: i64) {
        self.smin = self.smin.max(c);
        if c >= 0 {
            self.umin = self.umin.max(c as u64);
        }
        self.sync_bounds();
    }

    /// Apply unsigned constraint: value <= c
    #[allow(dead_code)]
    pub fn assume_ule(&mut self, c: u64) {
        self.umax = self.umax.min(c);
        if c <= i64::MAX as u64 {
            self.smax = self.smax.min(c as i64);
        }
        self.sync_bounds();
    }

    /// Apply unsigned constraint: value >= c
    #[allow(dead_code)]
    pub fn assume_uge(&mut self, c: u64) {
        self.umin = self.umin.max(c);
        if c <= i64::MAX as u64 && self.smin >= 0 {
            self.smin = self.smin.max(c as i64);
        }
        self.sync_bounds();
    }
}

impl Default for ScalarBounds {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Kernel `mark_pkt_end` relationship for a packet pointer that took the
/// "out of range" side of a `pkt OP pkt_end` comparison. Mirrors the
/// kernel's `reg->range` sentinels `AT_PKT_END` (-1) / `BEYOND_PKT_END`
/// (-2) (verifier.c `mark_pkt_end`). Used by `condition_outcome` to
/// resolve a *duplicated* `pkt vs pkt_end` comparison (a compiler artifact,
/// e.g. `test_tc_change_tail::change_tail`) so the contradictory
/// `pkt > end ∧ pkt <= end` path goes empty instead of reaching an
/// unrefined packet access. See kernel `is_pkt_ptr_branch_taken`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PktEndRel {
    /// `pkt == pkt_end` exactly (kernel `AT_PKT_END`): proven on the taken
    /// branch of `pkt >= pkt_end` (or `pkt <= pkt_end` fall-through).
    At,
    /// `pkt > pkt_end`, at least one byte beyond (kernel `BEYOND_PKT_END`):
    /// proven on the taken branch of `pkt > pkt_end`.
    Beyond,
}

/// Pointer offset information
/// Tracks the relationship between a register and its base anchor
/// Field names match Linux kernel's bpf_reg_state for clarity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtrOffset {
    /// Which anchor this pointer is relative to
    pub anchor: Reg,
    /// Fixed offset from the anchor (kernel: reg->off)
    pub off: i64,
    /// Variable offset uncertainty (kernel: tnum_range(reg->var_off))
    /// Actual offset is in [off, off + var_off]
    pub var_off: u64,
    /// Proven safe access range from this pointer (kernel: reg->range)
    /// After bounds check `if (ptr + N <= end)`, this is set to N
    /// Access check: off + size <= range
    pub range: Option<i64>,
    /// Kernel-style packet-pointer identity (kernel: reg->id).
    ///
    /// Allocated fresh whenever a pointer first picks up a *variable*
    /// offset — i.e. when a non-constant scalar is added to a packet
    /// pointer. Propagated unchanged through `Mov`, constant adds, and
    /// reg→reg copies; reset on overwrite.
    ///
    /// Two pointers with the same `Some(id)` are known to share their
    /// variable offset, so a bounds-check refinement (`if r > end`) on
    /// one propagates `range` to all members of the family. A `None`
    /// id means "no variable offset chain" — refinement only affects
    /// the triggering register itself.
    ///
    /// The id is the interval-mode analogue of relational tracking the
    /// zone domain expresses directly via DBM cells; without it the
    /// non-relational interval cannot tell apart two pointers that
    /// happen to share the same numeric `var_off` but came from
    /// independent arithmetic chains.
    pub id: Option<u32>,
    /// Kernel `mark_pkt_end` relationship (`reg->range` sentinels
    /// AT_PKT_END / BEYOND_PKT_END). `Some` only on the "out of range"
    /// branch of a `pkt vs pkt_end` comparison; reset to `None` on any
    /// pointer arithmetic and not round-tripped across spill/subprog
    /// boundaries (conservative — losing it only costs branch resolution,
    /// never soundness). See [`PktEndRel`].
    pub pkt_end_rel: Option<PktEndRel>,
}

impl PtrOffset {
    /// Kernel-equivalent `reg->range` value folding the proven good range
    /// (`>= 0`) together with the `mark_pkt_end` sentinels
    /// (`BEYOND_PKT_END = -2`, `AT_PKT_END = -1`). Used by subsumption to
    /// mirror the kernel `regsafe` rule `rold->range > rcur->range`.
    pub fn kernel_range(&self) -> i64 {
        match self.pkt_end_rel {
            Some(PktEndRel::Beyond) => -2,
            Some(PktEndRel::At) => -1,
            None => self.range.unwrap_or(0),
        }
    }
}

impl PtrOffset {
    /// Create offset info for a pointer equal to its anchor
    pub fn at_anchor(anchor: Reg) -> Self {
        PtrOffset {
            anchor,
            off: 0,
            var_off: 0,
            range: None,
            id: None,
            pkt_end_rel: None,
        }
    }

    /// Create offset info for a pointer at fixed offset from anchor
    #[allow(dead_code)]
    pub fn at_fixed(anchor: Reg, off: i64) -> Self {
        PtrOffset {
            anchor,
            off,
            var_off: 0,
            range: None,
            id: None,
            pkt_end_rel: None,
        }
    }

    /// Create offset info with variable range
    #[allow(dead_code)]
    pub fn with_var_off(anchor: Reg, off: i64, var_off: u64) -> Self {
        PtrOffset {
            anchor,
            off,
            var_off,
            range: None,
            id: None,
            pkt_end_rel: None,
        }
    }

    /// Get the minimum possible offset (off)
    pub fn min_offset(&self) -> i64 {
        self.off
    }

    /// Get the maximum possible offset (off + var_off)
    pub fn max_offset(&self) -> i64 {
        self.off.saturating_add(self.var_off as i64)
    }
}

/// Per-register state in the interval domain
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegInterval {
    /// Scalar bounds for this register
    pub bounds: ScalarBounds,
    /// Optional pointer offset info (set when register holds a tracked pointer)
    pub ptr_offset: Option<PtrOffset>,
}

impl RegInterval {
    pub fn unknown() -> Self {
        RegInterval {
            bounds: ScalarBounds::unknown(),
            ptr_offset: None,
        }
    }

    pub fn constant(val: i64) -> Self {
        RegInterval {
            bounds: ScalarBounds::constant(val),
            ptr_offset: None,
        }
    }

    pub fn with_ptr_offset(bounds: ScalarBounds, ptr_offset: PtrOffset) -> Self {
        RegInterval {
            bounds,
            ptr_offset: Some(ptr_offset),
        }
    }
}

impl Default for RegInterval {
    fn default() -> Self {
        Self::unknown()
    }
}

/// The interval domain state
/// Tracks per-register bounds without relational constraints
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntervalState {
    /// Per-register interval information
    /// Index by Reg::idx() - includes all 12 registers + 3 anchors
    regs: [RegInterval; Reg::DBM_DIM],

    /// Packet geometry: known relationship between data and data_end
    /// If Some(n), then data_end - data >= n (packet has at least n bytes)
    /// This is learned from successful bounds checks
    packet_size_lower_bound: Option<u64>,

    /// Packet geometry upper bound: if Some(n), then data_end - data < n
    /// This is learned when bounds checks FAIL (packet too small path)
    packet_size_upper_bound: Option<u64>,

    /// Meta region geometry: known relationship between data_meta and data
    /// If Some(n), then data - data_meta >= n (meta region has at least n bytes)
    /// This is learned from successful bounds checks
    meta_size_lower_bound: Option<u64>,

    /// Meta region upper bound: if Some(n), then data - data_meta < n
    meta_size_upper_bound: Option<u64>,
}

impl IntervalState {
    /// Create a new interval state with all registers unknown
    pub fn new() -> Self {
        let mut regs = std::array::from_fn(|_| RegInterval::unknown());

        // R0 (Zero) is always 0
        regs[Reg::Zero.idx()] = RegInterval::constant(0);

        // Initialize anchors to themselves at offset 0
        for anchor in [Reg::AnchorData, Reg::AnchorDataEnd, Reg::AnchorDataMeta] {
            regs[anchor.idx()] =
                RegInterval::with_ptr_offset(ScalarBounds::unknown(), PtrOffset::at_anchor(anchor));
        }

        // R10 is the stack frame pointer - track it as an anchor for stack offsets
        // This allows us to compute distances like (R10 - 8) - R10 = -8
        regs[Reg::R10.idx()] =
            RegInterval::with_ptr_offset(ScalarBounds::unknown(), PtrOffset::at_anchor(Reg::R10));

        IntervalState {
            regs,
            packet_size_lower_bound: None,
            packet_size_upper_bound: None,
            meta_size_lower_bound: None,
            meta_size_upper_bound: None,
        }
    }

    /// Get the interval for a register
    pub fn get(&self, r: Reg) -> &RegInterval {
        &self.regs[r.idx()]
    }

    /// Get mutable reference to register interval
    pub fn get_mut(&mut self, r: Reg) -> &mut RegInterval {
        &mut self.regs[r.idx()]
    }

    /// Set the interval for a register
    pub fn set(&mut self, r: Reg, interval: RegInterval) {
        if r != Reg::Zero {
            self.regs[r.idx()] = interval;
        }
    }

    /// Get scalar bounds for a register
    pub fn get_bounds(&self, r: Reg) -> &ScalarBounds {
        &self.regs[r.idx()].bounds
    }

    /// Get mutable reference to scalar bounds
    pub fn get_bounds_mut(&mut self, r: Reg) -> &mut ScalarBounds {
        &mut self.regs[r.idx()].bounds
    }

    /// Get pointer offset info for a register
    pub fn get_ptr_offset(&self, r: Reg) -> Option<&PtrOffset> {
        self.regs[r.idx()].ptr_offset.as_ref()
    }

    /// Set pointer offset info for a register
    #[allow(dead_code)]
    pub fn set_ptr_offset(&mut self, r: Reg, offset: Option<PtrOffset>) {
        if r != Reg::Zero {
            self.regs[r.idx()].ptr_offset = offset;
        }
    }

    /// Get the [min, max] interval for a register (signed)
    pub fn get_interval(&self, r: Reg) -> (i64, i64) {
        let bounds = &self.regs[r.idx()].bounds;
        (bounds.smin, bounds.smax)
    }

    /// Check if register has a fixed (constant) value
    pub fn get_fixed_value(&self, r: Reg) -> Option<i64> {
        self.regs[r.idx()].bounds.get_constant()
    }

    /// Forget all information about a register
    pub fn forget(&mut self, r: Reg) {
        if r != Reg::Zero && !r.is_anchor() {
            self.regs[r.idx()] = RegInterval::unknown();
        }
    }

    /// Record that packet has at least n bytes (from bounds check).
    ///
    /// **Disabled in the kernel-faithful Interval domain** because the
    /// upstream kernel does NOT track a global packet_size — it tracks
    /// `reg->range` per packet pointer only, so two independent packet
    /// pointers can have independent ranges. Aggregating bounds globally
    /// is a zovia-specific over-precision that would prune paths the
    /// kernel still explores, so this is unconditionally a no-op in
    /// this domain.
    pub fn set_packet_size_bound(&mut self, _min_size: u64) {}

    /// Get known lower bound on packet size. Always `None` after the
    /// kernel-faithfulness disable above — kept for source compatibility
    /// with the gate-on-update site in `interval_packet.rs`.
    pub fn get_packet_size_bound(&self) -> Option<u64> {
        self.packet_size_lower_bound
    }

    /// Record that packet has fewer than n bytes (packet too small path).
    /// Disabled for kernel-faithfulness; see [`set_packet_size_bound`].
    pub fn set_packet_size_upper_bound(&mut self, _max_size_exclusive: u64) {}

    /// Record that meta region has at least n bytes (from bounds check).
    /// Disabled for kernel-faithfulness (same reason as
    /// [`set_packet_size_bound`] — kernel tracks per-pointer
    /// `reg->range`, not a global meta_size).
    pub fn set_meta_size_bound(&mut self, _min_size: u64) {}

    /// Get known lower bound on meta region size. Always `None` post the
    /// kernel-faithfulness disable above.
    pub fn get_meta_size_bound(&self) -> Option<u64> {
        self.meta_size_lower_bound
    }

    /// Record that meta region has fewer than n bytes. Disabled for
    /// kernel-faithfulness (see [`set_meta_size_bound`]).
    pub fn set_meta_size_upper_bound(&mut self, _max_size_exclusive: u64) {}

    /// Compact string of global (non-per-register) constraints for log lines.
    ///
    /// The only relational state in Interval mode that is not captured by
    /// per-register PtrOffset info is the packet / meta geometry learned from
    /// bounds checks.  Outputs tokens like `pkt>=100` or `pkt in [100,200)`.
    /// Returns an empty string when nothing is constrained.
    pub fn global_constraints_str(&self) -> String {
        let mut parts: Vec<String> = Vec::new();

        match (self.packet_size_lower_bound, self.packet_size_upper_bound) {
            (Some(lo), Some(hi)) => parts.push(format!("pkt in [{},{})", lo, hi)),
            (Some(lo), None) => parts.push(format!("pkt>={}", lo)),
            (None, Some(hi)) => parts.push(format!("pkt<{}", hi)),
            (None, None) => {}
        }

        match (self.meta_size_lower_bound, self.meta_size_upper_bound) {
            (Some(lo), Some(hi)) => parts.push(format!("meta in [{},{})", lo, hi)),
            (Some(lo), None) => parts.push(format!("meta>={}", lo)),
            (None, Some(hi)) => parts.push(format!("meta<{}", hi)),
            (None, None) => {}
        }

        parts.join("  ")
    }

    /// Clear all packet and meta size bounds.
    /// Called when entering a function to ensure the callee starts fresh,
    /// matching kernel verifier behavior where each function tracks its own bounds.
    pub fn clear_packet_size_bounds(&mut self) {
        self.packet_size_lower_bound = None;
        self.packet_size_upper_bound = None;
        self.meta_size_lower_bound = None;
        self.meta_size_upper_bound = None;
    }

    /// Check if the domain state is inconsistent (infeasible)
    pub fn is_inconsistent(&self) -> bool {
        // Check register bounds
        for reg in &self.regs {
            if reg.bounds.smin > reg.bounds.smax || reg.bounds.umin > reg.bounds.umax {
                return true;
            }
        }

        // Check packet size bounds: if lower >= upper, infeasible
        // lower_bound means packet_size >= lower
        // upper_bound means packet_size < upper (exclusive)
        // So if lower >= upper, we have packet_size >= lower AND packet_size < upper
        // which is impossible when lower >= upper
        if let (Some(lower), Some(upper)) =
            (self.packet_size_lower_bound, self.packet_size_upper_bound)
            && lower >= upper {
                return true;
            }

        // Check meta size bounds similarly
        if let (Some(lower), Some(upper)) = (self.meta_size_lower_bound, self.meta_size_upper_bound)
            && lower >= upper {
                return true;
            }

        false
    }
}

impl Default for IntervalState {
    fn default() -> Self {
        Self::new()
    }
}
