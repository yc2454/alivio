// src/analysis/machine/stack_ops.rs
//
// Stack spill / reload / anchor-restore methods for `State`. Split from
// state.rs to keep that file focused on the core model; these are the
// heavyweight implementations (~500 lines) that translate between register
// values and StackState slots.

use crate::analysis::machine::frame_stack::FrameLevel;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::stack_state::{ScalarBounds, SpilledReg};
use crate::analysis::transfer::alu::helpers::bcf_reg_bounds;
use crate::ast::MemSize;
use crate::domains::dbm::INF;
use crate::domains::numeric::NumericDomain;
use crate::domains::tnum::Tnum;
use log::trace;

use super::state::State;

impl State {
    /// Spill into a specific frame (cross-frame, e.g. store via PtrToStack)
    pub fn spill_at(&mut self, level: FrameLevel, reg: Reg, offset: i16, size: MemSize) {
        let is_aligned = (offset % 8) == 0;
        let reg_type = self.types.get(reg);

        // Kernel `check_stack_write_fixed_off` (verifier.c:5544) classification:
        //   (a) aligned (off%8==0) SCALAR register store, ANY size → STACK_SPILL
        //       with the value saved (small-spill support);
        //   (c) spillable-pointer register store (necessarily aligned 8-byte;
        //       partial pointer spills are EACCES upstream) → STACK_SPILL;
        //   (d) everything else — an UNALIGNED register store — DESTROYS the
        //       value: covered bytes become STACK_MISC (STACK_ZERO when the
        //       source register is a known null, which the kernel also forces
        //       precise).
        // The SPILL-vs-MISC byte-kind distinction matters for state
        // subsumption: the kernel keeps such paths apart on byte kinds.
        if !(is_aligned && (matches!(reg_type, RegType::ScalarValue) || size == MemSize::U64)) {
            let is_null =
                matches!(reg_type, RegType::ScalarValue) && self.domain.proven_zero(reg);
            let kind = if is_null {
                crate::analysis::machine::stack_state::StackSlotKind::Zero
            } else {
                crate::analysis::machine::stack_state::StackSlotKind::Misc
            };
            if is_null {
                // Kernel: "force originating register to be precise to make
                // STACK_ZERO correct for subsequent states". Local-state mark
                // only; the backward chain walk happens at the usual
                // precision sinks.
                self.precise_regs.insert(reg);
            }
            let stack = &mut self.frames.get_mut(level).stack;
            // Kernel else-branch whole-slot scrub (verifier.c:5641) —
            // see scrub_spilled_slots_for_write.
            stack.scrub_spilled_slots_for_write(offset, size.bytes());
            for i in 0..size.bytes() {
                stack.insert(
                    offset + i as i16,
                    SpilledReg {
                        source_reg: None,
                        reg_type: RegType::ScalarValue,
                        tnum: if is_null {
                            Tnum::constant(0)
                        } else {
                            Tnum::unknown()
                        },
                        bounds: if is_null {
                            ScalarBounds { min: 0, max: 0 }
                        } else {
                            ScalarBounds {
                                min: i64::MIN,
                                max: i64::MAX,
                            }
                        },
                        size,
                        ptr_bounds: None,
                        scalar_id: None,
                        scalar_id_off: None,
                        precise: false,
                        ptr_const_off: None,
                        iterator: None,
                        dynptr: None,
                        irq_flag: None,
                        bcf_expr: None,
                        kind,
                    },
                );
            }
            return;
        }

        // Only U64 stores at aligned offsets can preserve pointer types
        let preserved_type = if size == MemSize::U64 && is_aligned {
            reg_type
        } else {
            RegType::ScalarValue
        };

        // Save pointer bounds if applicable
        let ptr_bounds = if size == MemSize::U64 && is_aligned {
            use crate::analysis::machine::stack_state::PointerBounds;
            let (i_off, i_var, i_range, i_id) = self.save_interval_ptr_offset(reg);
            if i_off.is_some() || i_var.is_some() || i_range.is_some() {
                Some(PointerBounds::Interval {
                    off: i_off,
                    var_off: i_var,
                    range: i_range,
                    id: i_id,
                })
            } else {
                let (a, lo, hi) = self.save_anchor_info(reg);
                let (ea, elo, ehi) = self.save_secondary_anchor_info(reg);
                if a.is_some()
                    || lo.is_some()
                    || hi.is_some()
                    || ea.is_some()
                    || elo.is_some()
                    || ehi.is_some()
                {
                    Some(PointerBounds::Zone {
                        anchor: a,
                        anchor_lo: lo,
                        anchor_hi: hi,
                        end_anchor: ea,
                        end_lo: elo,
                        end_hi: ehi,
                    })
                } else {
                    None
                }
            }
        } else {
            None
        };

        let (min, max) = self.domain.get_interval(reg);
        trace!("At spilling, {} bounds: [{}, {}]", reg.name(), min, max);

        // Only track as proper spill if 8-byte aligned
        let source_reg = if is_aligned { Some(reg) } else { None };

        // Scalar-id at spill — kernel check_stack_write_fixed_off
        // (verifier.c:5604-5615): an ALIGNED scalar spill links slot and
        // source ONLY when the value FITS the store width
        // (`reg_value_fits = get_reg_width(reg) <= size*8`, fls64 of
        // umax) — then `assign_scalar_id_before_mov` (a) clears an
        // ADD_CONST link on the source, (b) assigns a fresh id only if
        // the source has none AND `!tnum_is_const(var_off)` (consts
        // never link). A NARROWING spill breaks the relation
        // (`spilled_ptr.id = 0`). The old zovia gate (`size <= 8`, no
        // const/width checks) linked consts and truncated values the
        // kernel keeps unlinked, feeding the sync_linked_regs-mirror
        // fanout with links the kernel can't have.
        let slot_scalar_id = if is_aligned
            && matches!(preserved_type, RegType::ScalarValue)
        {
            let umax: u64 = if min < 0 { u64::MAX } else { max as u64 };
            let reg_width = 64 - umax.leading_zeros() as usize;
            let reg_value_fits = reg_width <= size.bytes() * 8;
            if reg_value_fits {
                // assign_scalar_id_before_mov: ADD_CONST links are
                // cleared on the source first (multiple `+= const`
                // chains unsupported, kernel comment).
                if self.scalar_id_off.contains_key(&reg) {
                    self.scalar_ids.remove(&reg);
                    self.scalar_id_off.remove(&reg);
                }
                // Kernel `tnum_is_const(var_off)`; zovia's tnum map can
                // lag the interval domain, so a pinned interval counts
                // as const too (a kernel reg with umin==umax always has
                // const var_off).
                let is_const = min == max
                    || self
                        .tnums
                        .get(&reg)
                        .map(|t| t.is_const())
                        .unwrap_or(false);
                match self.scalar_ids.get(&reg).copied() {
                    Some(id) => Some(id),
                    None if !is_const => {
                        let new_id =
                            crate::analysis::machine::reg_types::new_scalar_id();
                        self.scalar_ids.insert(reg, new_id);
                        Some(new_id)
                    }
                    None => None,
                }
            } else {
                None // narrowing spill: kernel breaks the relation
            }
        } else if size == MemSize::U64 && is_aligned {
            self.scalar_ids.get(&reg).copied()
        } else {
            None
        };

        // BCF symbolic carry. Mirrors kernel `save_register_state`
        // (verifier.c:5478): `copy_register_state` copies `bcf_expr`
        // verbatim, then for a sub-64 spill of a non-const scalar
        // `bcf_mov(env, &spilled_ptr, reg, size*8, false, false)`
        // (verifier.c:16352) rewrites it to
        // `ZEXT_64( EXTRACT_{size*8}( bcf_reg_expr(reg, sz==32) ) )`.
        // Gate matches `check_stack_write_fixed_off` (verifier.c:5598):
        // an 8-byte-aligned scalar spill only.
        let slot_bcf_expr: Option<u32> = if is_aligned
            && size.bytes() <= 8
            && matches!(preserved_type, RegType::ScalarValue)
        {
            if let Some(src_idx) = reg.bcf_idx() {
                let src_tnum =
                    self.tnums.get(&reg).cloned().unwrap_or(Tnum::unknown());
                if size == MemSize::U64 || src_tnum.is_const() {
                    // size == BPF_REG_SIZE → bcf_mov not called; const
                    // var_off → kernel `!tnum_is_const` gate skips
                    // bcf_mov. Either way: verbatim copy_register_state.
                    self.bcf.as_ref().and_then(|b| b.get_reg(src_idx))
                } else {
                    let sz_bits = (size.bytes() as u16) * 8;
                    let subreg = sz_bits == 32;
                    let src_bounds = bcf_reg_bounds(self, reg);
                    self.bcf.as_mut().map(|b| {
                        let mut e = b.reg_expr(src_idx, &src_bounds, subreg);
                        if sz_bits != 32 {
                            e = b.add_extract(sz_bits, e);
                        }
                        b.add_extend(false, 64 - sz_bits, 64, e)
                    })
                }
            } else {
                None
            }
        } else {
            None
        };

        let spilled = SpilledReg {
            source_reg,
            reg_type: preserved_type,
            tnum: self.tnums.get(&reg).cloned().unwrap_or(Tnum::unknown()),
            bounds: ScalarBounds { min, max },
            size,
            ptr_bounds,
            scalar_id: slot_scalar_id,
            // Kernel save_register_state copies the full reg incl the
            // BPF_ADD_CONST delta (reg->off) — a spilled add-const link
            // keeps its delta for sync_linked_regs.
            scalar_id_off: if slot_scalar_id.is_some() {
                self.scalar_id_off.get(&reg).copied()
            } else {
                None
            },
            precise: is_aligned && size == MemSize::U64 && self.precise_regs.contains(&reg),
            iterator: None,
            dynptr: None,
                    irq_flag: None,
            bcf_expr: slot_bcf_expr,
            // Carry the const pointer offset (kernel copy_register_state
            // preserves var_off/off across spill). Only meaningful for an
            // aligned U64 pointer spill; sub-64 / unaligned spills lose the
            // pointer anyway, so a None there matches.
            ptr_const_off: if is_aligned && size == MemSize::U64 {
                self.ptr_const_off.get(&reg).copied()
            } else {
                None
            },
            // Register spilled into the stack (kernel STACK_SPILL).
            kind: crate::analysis::machine::stack_state::StackSlotKind::Spill,
        };

        let stack = &mut self.frames.get_mut(level).stack;
        for i in 0..size.bytes() {
            let current_byte = offset + i as i16;
            if i == 0 {
                stack.insert(current_byte, spilled.clone());
            } else {
                stack.insert(
                    current_byte,
                    SpilledReg {
                        source_reg: None,
                        reg_type: RegType::ScalarValue,
                        tnum: Tnum::unknown(),
                        bounds: ScalarBounds {
                            min: i64::MIN,
                            max: i64::MAX,
                        },
                        size,
                        ptr_bounds: None,
                        scalar_id: None,
                        scalar_id_off: None,
                        precise: false,
            ptr_const_off: None,
                        iterator: None,
                        dynptr: None,
                    irq_flag: None,
                        bcf_expr: None,
                        // Trailing byte of a spilled register (kernel STACK_SPILL).
                        kind: crate::analysis::machine::stack_state::StackSlotKind::Spill,
                    },
                );
            }
        }
        // Kernel `save_register_state` sub-8 spill remainder scrub — the
        // remainder bytes go through `mark_stack_slot_misc`
        // (verifier.c:1665), NOT `scrub_spilled_slot`: **STACK_ZERO and
        // STACK_INVALID are PRESERVED**, only other kinds become
        // STACK_MISC. Stale SPILL residue still becomes MISC.
        if is_aligned && size.bytes() < 8 {
            for b in (offset + size.bytes() as i16)..(offset + 8) {
                if matches!(
                    stack.get_slot_kind(b),
                    Some(k) if k != crate::analysis::machine::stack_state::StackSlotKind::Zero
                ) {
                    stack.insert(
                        b,
                        SpilledReg {
                            source_reg: None,
                            reg_type: RegType::ScalarValue,
                            tnum: Tnum::unknown(),
                            bounds: ScalarBounds {
                                min: i64::MIN,
                                max: i64::MAX,
                            },
                            size,
                            ptr_bounds: None,
                            scalar_id: None,
                            scalar_id_off: None,
                            precise: false,
                            ptr_const_off: None,
                            iterator: None,
                            dynptr: None,
                            irq_flag: None,
                            bcf_expr: None,
                            kind: crate::analysis::machine::stack_state::StackSlotKind::Misc,
                        },
                    );
                }
            }
        }
    }

    pub fn store_imm_to_stack_at(
        &mut self,
        level: FrameLevel,
        imm: i64,
        offset: i16,
        size: MemSize,
    ) {
        let is_aligned = (offset % 8) == 0;

        // Mask the immediate value to the store size
        let masked_imm = match size {
            MemSize::U8 => (imm as u8) as i64,
            MemSize::U16 => (imm as u16) as i64,
            MemSize::U32 => (imm as u32) as i64,
            MemSize::U64 => imm,
        };

        // Kernel `check_stack_write_fixed_off` (verifier.c:5544) for BPF_ST:
        //   (b) ALIGNED const store → save_register_state of a known-const
        //       fake reg = STACK_SPILL with the value (even for zero);
        //   (d) UNALIGNED: imm==0 → STACK_ZERO; otherwise STACK_MISC with the
        //       value DESTROYED (the kernel's else-branch keeps no constant).
        let store_kind = if is_aligned {
            crate::analysis::machine::stack_state::StackSlotKind::Spill
        } else if masked_imm == 0 {
            crate::analysis::machine::stack_state::StackSlotKind::Zero
        } else {
            crate::analysis::machine::stack_state::StackSlotKind::Misc
        };
        let (tnum, bounds) = if matches!(
            store_kind,
            crate::analysis::machine::stack_state::StackSlotKind::Misc
        ) {
            (
                Tnum::unknown(),
                ScalarBounds {
                    min: i64::MIN,
                    max: i64::MAX,
                },
            )
        } else {
            (
                Tnum::constant(masked_imm as u64),
                ScalarBounds {
                    min: masked_imm,
                    max: masked_imm,
                },
            )
        };

        let slot_content = SpilledReg {
            source_reg: if is_aligned { Some(Reg::R0) } else { None }, // Use dummy reg to indicate "trackable"
            reg_type: RegType::ScalarValue,
            tnum,
            bounds,
            size,
            ptr_bounds: None,
            scalar_id: None,
            scalar_id_off: None,
            precise: false,
            ptr_const_off: None,
            iterator: None,
            dynptr: None,
                    irq_flag: None,
            // Const-imm store: kernel `is_bpf_st_mem` path builds a
            // known-const fake_reg whose `var_off` is const, so the
            // `bcf_mov` gate is skipped and no variable expr is carried.
            // The constant lazy-materializes as `BV_VAL` on fill.
            bcf_expr: None,
            kind: store_kind,
        };

        let stack = &mut self.frames.get_mut(level).stack;
        // Kernel else-branch whole-slot scrub (verifier.c:5641) applies to
        // the UNALIGNED BPF_ST path too — see scrub_spilled_slots_for_write.
        if !is_aligned {
            stack.scrub_spilled_slots_for_write(offset, size.bytes());
        }
        for i in 0..size.bytes() {
            let current_byte = offset + i as i16;
            if i == 0 {
                stack.insert(current_byte, slot_content.clone());
            } else {
                stack.insert(
                    current_byte,
                    SpilledReg {
                        source_reg: None,
                        reg_type: RegType::ScalarValue,
                        tnum: Tnum::unknown(),
                        bounds: ScalarBounds {
                            min: i64::MIN,
                            max: i64::MAX,
                        },
                        size,
                        ptr_bounds: None,
                        scalar_id: None,
                        scalar_id_off: None,
                        precise: false,
            ptr_const_off: None,
                        iterator: None,
                        dynptr: None,
                    irq_flag: None,
                        bcf_expr: None,
                        // Trailing byte shares the store's slot kind (STACK_ZERO
                        // for a zero store, else the known-value STACK_SPILL).
                        kind: store_kind,
                    },
                );
            }
        }
        // Kernel BPF_ST aligned path routes through save_register_state
        // too (fake const reg), so a sub-8 ST-imm scrubs the slot
        // remainder with the same `mark_stack_slot_misc` rule:
        // STACK_ZERO and STACK_INVALID preserved, everything else
        // becomes STACK_MISC. (Was previously missing entirely.)
        if is_aligned && size.bytes() < 8 {
            for b in (offset + size.bytes() as i16)..(offset + 8) {
                if matches!(
                    stack.get_slot_kind(b),
                    Some(k) if k != crate::analysis::machine::stack_state::StackSlotKind::Zero
                ) {
                    stack.insert(
                        b,
                        SpilledReg {
                            source_reg: None,
                            reg_type: RegType::ScalarValue,
                            tnum: Tnum::unknown(),
                            bounds: ScalarBounds {
                                min: i64::MIN,
                                max: i64::MAX,
                            },
                            size,
                            ptr_bounds: None,
                            scalar_id: None,
                            scalar_id_off: None,
                            precise: false,
                            ptr_const_off: None,
                            iterator: None,
                            dynptr: None,
                            irq_flag: None,
                            bcf_expr: None,
                            kind: crate::analysis::machine::stack_state::StackSlotKind::Misc,
                        },
                    );
                }
            }
        }
    }

    /// Reload from current frame
    pub fn fill(&mut self, dst: Reg, offset: i16, size: MemSize) -> bool {
        let level = self.frames.current_level();
        self.fill_at(level, dst, offset, size)
    }

    /// Reload from a specific frame (cross-frame)
    pub fn fill_at(&mut self, level: FrameLevel, dst: Reg, offset: i16, size: MemSize) -> bool {
        let stack = &self.frames.get(level).stack;

        // Check all bytes we're reading are initialized
        for i in 0..size.bytes() {
            let current_byte = offset + i as i16;
            if stack.get_slot(current_byte).is_none() {
                return false; // Reading uninitialized memory
            }
        }

        // Get the slot at base offset
        let spilled = match stack.get_slot(offset).cloned() {
            Some(s) => s,
            None => return false,
        };

        self.domain.forget(dst);
        // dst is being overwritten by the fill — drop any stale const
        // pointer offset; the aligned-U64 pointer-restore branch below
        // re-inserts the carried offset when present.
        self.ptr_const_off.remove(&dst);

        // Check if we can preserve type/bounds:
        // 1. Must be reading from start of a spilled value (source_reg.is_some())
        // 2. Load size must match store size
        // 3. Offset must be 8-byte aligned
        let is_aligned = (offset % 8) == 0;
        let sizes_match = spilled.source_reg.is_some() && spilled.size == size;


        // Try to extract a precise (sub-)value when reading a narrower
        // (or unaligned) slice of a wider spill whose enclosing tnum
        // pins enough bits. Walk back up to 7 bytes to find the slot
        // holding the actual spilled value. Placeholder bytes have
        // tnum=unknown (mask=u64::MAX) and large size, so the
        // alignment+const gates below let real spills win the search.
        let narrowed_tnum: Option<Tnum> = if !sizes_match && size.bytes() <= 8 {
            let mut found: Option<Tnum> = None;
            for back in 0..8i16 {
                let base = offset - back;
                if let Some(s) = stack.get_slot(base) {
                    // Aligned-base aligned-width spills are the only
                    // ones we trust beyond the simple zero (STACK_ZERO)
                    // case — kernel marks unaligned register spills
                    // STACK_MISC. We treat constant-zero stores as
                    // safe at any alignment to model STACK_ZERO.
                    let base_aligned = base % 8 == 0;
                    let covers = (back as usize) + size.bytes() <= s.size.bytes();
                    if !covers {
                        continue;
                    }
                    let trustable = base_aligned || (s.tnum.is_const() && s.tnum.value == 0);
                    if !trustable {
                        continue;
                    }
                    let shift = (back as u64) * 8;
                    let v = s.tnum.value >> shift;
                    let m = s.tnum.mask >> shift;
                    let mask: u64 = match size {
                        MemSize::U8 => 0xff,
                        MemSize::U16 => 0xffff,
                        MemSize::U32 => 0xffff_ffff,
                        MemSize::U64 => u64::MAX,
                    };
                    let nm = m & mask;
                    // Nothing pinned within the fill width → no info beyond
                    // the existing unbounded fallback. Skip to avoid spurious
                    // bounds (e.g. signed-overflow at U64) and pointless work.
                    if nm == mask {
                        break;
                    }
                    found = Some(Tnum {
                        value: v & mask,
                        mask: nm,
                    });
                    break;
                }
            }
            found
        } else {
            None
        };

        // Special case: u32 LE-low fill of an aligned u64 scalar spill
        // whose high 32 bits are known zero. The low half carries the
        // full spilled value, so preserve tnum, bounds AND scalar_id —
        // matching kernel's u32-fill-after-u64-spill-preserve-id rule.
        // (Counterpart `_clear_id` test fails the high-bits-zero check.)
        if !sizes_match
            && size == MemSize::U32
            && spilled.size == MemSize::U64
            && is_aligned
            && spilled.source_reg.is_some()
            && matches!(spilled.reg_type, RegType::ScalarValue)
            && (spilled.tnum.mask & 0xFFFFFFFF_00000000) == 0
            && (spilled.tnum.value >> 32) == 0
        {
            self.types.set(dst, RegType::ScalarValue);
            self.tnums.insert(dst, spilled.tnum.clone());
            self.domain
                .assign_interval(dst, spilled.bounds.min, spilled.bounds.max);
            if let Some(id) = spilled.scalar_id {
                self.scalar_ids.insert(dst, id);
            } else {
                self.scalar_ids.remove(&dst);
            }
            match spilled.scalar_id_off {
                Some(off) if spilled.scalar_id.is_some() => {
                    self.scalar_id_off.insert(dst, off);
                }
                _ => {
                    self.scalar_id_off.remove(&dst);
                }
            }
            if spilled.precise {
                self.precise_regs.insert(dst);
            } else {
                self.precise_regs.remove(&dst);
            }
            // Kernel narrowing-fill (`size <= spill_size`,
            // `bpf_stack_narrow_access_ok`) copies the slot's reg state
            // verbatim — including `bcf_expr` — then only breaks the
            // scalar `id` (check_stack_read_fixed_off:5889/5896). The
            // carried symbolic value is the full spilled expr.
            restore_slot_bcf_expr(self, dst, spilled.bcf_expr);
            return true;
        }

        if sizes_match && is_aligned {
            // Pre-fill capture for the slot-share adoption below: when the
            // fill TARGET itself is the live copy of this slot's value
            // (same scalar id — e.g. a loop-invariant refilled into the
            // same reg each iteration), its binding and id are clobbered
            // by the restore sequence before the share block runs.
            let pre_fill_dst_binding: Option<u32> = if spilled.scalar_id.is_some()
                && self.scalar_ids.get(&dst).copied() == spilled.scalar_id
            {
                dst.bcf_idx()
                    .and_then(|ri| self.bcf.as_ref().and_then(|b| b.get_reg(ri)))
            } else {
                None
            };
            // Preserve type and bounds
            self.types.set(dst, spilled.reg_type);
            self.tnums.insert(dst, spilled.tnum);
            self.domain
                .assign_interval(dst, spilled.bounds.min, spilled.bounds.max);

            // Restore scalar id so the filled register remains part of any
            // existing copy chain (e.g. a spilled then reloaded r1 shares the
            // same id as copies of it that stayed in registers).
            if let Some(id) = spilled.scalar_id {
                self.scalar_ids.insert(dst, id);
            } else {
                self.scalar_ids.remove(&dst);
            }
            // Restore the kernel BPF_ADD_CONST delta alongside the id
            // (copy_register_state preserves id|BPF_ADD_CONST + off).
            match spilled.scalar_id_off {
                Some(off) if spilled.scalar_id.is_some() => {
                    self.scalar_id_off.insert(dst, off);
                }
                _ => {
                    self.scalar_id_off.remove(&dst);
                }
            }

            // Restore precision mark carried at spill time.
            if spilled.precise {
                self.precise_regs.insert(dst);
            } else {
                self.precise_regs.remove(&dst);
            }

            // Restore the const pointer offset carried at spill time
            // (kernel copy_register_state preserves var_off/off). Without
            // this a filled packet pointer comes back with no const offset
            // and leaks into the BCF reject reg_masks. U64-only: a pointer
            // never survives a narrower fill.
            if size == MemSize::U64 {
                match spilled.ptr_const_off {
                    Some(k) => {
                        self.ptr_const_off.insert(dst, k);
                    }
                    None => {
                        self.ptr_const_off.remove(&dst);
                    }
                }
            } else {
                self.ptr_const_off.remove(&dst);
            }

            // Only restore anchors for U64 (pointers need full 64-bit)
            if size == MemSize::U64 {
                self.restore_anchor_info(dst, &spilled);
            }
            // Kernel `copy_register_state(&regs[dst], reg)` restores the
            // slot's `bcf_expr` verbatim on a same-size aligned fill
            // (check_stack_read_fixed_off:5934). `None` (== kernel -1)
            // clears, so the next use lazy-materializes a fresh expr.
            restore_slot_bcf_expr(self, dst, spilled.bcf_expr);
            // Replay slot-share variant (kernel bcf_track bt slot-demand
            // materialization): the first fill of an expr-less spilled
            // non-const scalar mints the VAR into the SLOT so every later
            // fill of this offset reuses it — the kernel's bt walk demands
            // the SLOT (not the transient reg) and materializes it once;
            // each fill then carries the one expr via copy_register_state.
            // Kernel `!tnum_is_const` guard mirrored; replay_share_slot_vars
            // is set only inside slot-share replay variants.
            if spilled.bcf_expr.is_none()
                && matches!(spilled.reg_type, RegType::ScalarValue)
                && self.domain.get_fixed_value(dst).is_none()
                && !self.get_tnum(dst).is_const()
                && self
                    .bcf
                    .as_ref()
                    .is_some_and(|b| b.replay_share_slot_vars)
                && let Some(idx) = dst.bcf_idx()
            {
                // Kernel demand-through-copy: the bt walk traces a COPY of
                // this slot's value (same scalar id — fills copy the id via
                // copy_register_state) back THROUGH its fill into the SLOT,
                // so the slot and every live copy share ONE var. If a reg
                // already materialized the value earlier in this replay
                // (the anchor-held copy, minted lazily at its first use),
                // ADOPT that expr for the slot instead of minting a second
                // var, so the slot and all copies share one var.
                let adopted: Option<u32> = pre_fill_dst_binding.or_else(|| {
                    spilled.scalar_id.and_then(|sid| {
                        Reg::ALL.iter().find_map(|&r| {
                            if r != dst && self.scalar_ids.get(&r) == Some(&sid) {
                                r.bcf_idx()
                                    .and_then(|ri| self.bcf.as_ref().and_then(|b| b.get_reg(ri)))
                            } else {
                                None
                            }
                        })
                    })
                });
                if std::env::var("ZOVIA_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1") {
                    let dst_bind = dst
                        .bcf_idx()
                        .and_then(|ri| self.bcf.as_ref().and_then(|b| b.get_reg(ri)));
                    let ids: Vec<String> = crate::analysis::machine::reg::Reg::ALL
                        .iter()
                        .filter_map(|&r| {
                            self.scalar_ids.get(&r).map(|id| format!("{:?}={}", r, id))
                        })
                        .collect();
                    eprintln!(
                        "[slot-share] pc={} off={} spilled_id={:?} dst={:?} post_dst_bind={:?} pre_fill_binding={:?} adopted={:?} ids=[{}]",
                        self.pc, offset, spilled.scalar_id, dst, dst_bind, pre_fill_dst_binding, adopted,
                        ids.join(" ")
                    );
                }
                let pc = self.pc;
                let expr = if let Some(e) = adopted {
                    if let Some(b) = self.bcf.as_mut() {
                        b.set_current_pc(pc);
                        b.bind_reg(idx, e);
                    }
                    Some(e)
                } else {
                    let bounds = bcf_reg_bounds(self, dst);
                    self.bcf.as_mut().map(|b| {
                        b.set_current_pc(pc);
                        b.reg_expr(idx, &bounds, false)
                    })
                };
                if let Some(e) = expr
                    && let Some(slot) = self.frames.get_mut(level).stack.get_slot_mut(offset)
                {
                    slot.bcf_expr = Some(e);
                }
            }
        } else if let Some(tn) = narrowed_tnum {
            // Narrowing read of a wider spill whose tnum pins (some of)
            // the bits we're loading (any byte offset within the wider
            // value, LE byte order).
            self.types.set(dst, RegType::ScalarValue);
            let v = tn.value;
            let m = tn.mask;
            // Bounds derived from the narrowed tnum: low = pinned bits,
            // high = pinned | unknown bits. For partial-knowledge tnums
            // this is the tightest interval we can claim without the
            // spill-time bounds.
            let lo = v as i64;
            let hi = (v | m) as i64;
            self.tnums.insert(dst, tn);
            self.domain.assign_interval(dst, lo, hi);
            self.scalar_ids.remove(&dst);
            self.scalar_id_off.remove(&dst);
            self.precise_regs.remove(&dst);
            // zovia-only tnum sub-slice precision; the kernel reaches
            // these states via __mark_reg_unknown (bcf_expr = -1). Clear
            // so we never carry a false whole-slot expr for a sub-read.
            restore_slot_bcf_expr(self, dst, None);
        } else {
            // Size mismatch or unaligned - return unbounded scalar for the load size
            self.types.set(dst, RegType::ScalarValue);
            let (min, max) = size.unbounded_scalar_bounds();
            self.tnums.insert(dst, Tnum::unknown());
            self.domain.assign_interval(dst, min, max);
            self.scalar_ids.remove(&dst);
            self.scalar_id_off.remove(&dst);
            self.precise_regs.remove(&dst);
            // Kernel mark_reg_unknown path → bcf_expr = -1.
            restore_slot_bcf_expr(self, dst, None);
        }

        true
    }

    pub fn save_anchor_info(&self, reg: Reg) -> (Option<Reg>, Option<i64>, Option<i64>) {
        let anchor = match self.types.get(reg) {
            RegType::PtrToPacket => Some(Reg::AnchorData),
            RegType::PtrToPacketMeta => Some(Reg::AnchorDataMeta),
            RegType::PtrToPacketEnd => Some(Reg::AnchorDataEnd),
            _ => None,
        };

        if let Some(a) = anchor {
            let hi = self.domain.get(reg, a); // reg - anchor <= hi
            let lo = self.domain.get(a, reg); // anchor - reg <= lo  (i.e., reg - anchor >= -lo)
            let hi = if hi >= INF { None } else { Some(hi) };
            let lo = if lo >= INF { None } else { Some(lo) };
            (Some(a), lo, hi)
        } else {
            (None, None, None)
        }
    }

    /// Save a packet pointer's secondary anchor relation (the @data_end
    /// edge for PtrToPacket / PtrToPacketMeta, or the @data edge for
    /// PtrToPacketEnd). Returns `(None, None, None)` for non-packet
    /// pointers and when the constraint is INF.
    ///
    /// Needed alongside `save_anchor_info` because the relations between
    /// distinct packet anchors are bounded but not fixed: a `r - @data`
    /// bound preserved across spill/fill is insufficient on its own to
    /// reconstruct a tighter `r - @data_end` bound that the access-site
    /// `end_ok` check depends on.
    pub fn save_secondary_anchor_info(
        &self,
        reg: Reg,
    ) -> (Option<Reg>, Option<i64>, Option<i64>) {
        let secondary = match self.types.get(reg) {
            RegType::PtrToPacket | RegType::PtrToPacketMeta => Some(Reg::AnchorDataEnd),
            RegType::PtrToPacketEnd => Some(Reg::AnchorData),
            _ => None,
        };

        if let Some(a) = secondary {
            let hi = self.domain.get(reg, a);
            let lo = self.domain.get(a, reg);
            let hi = if hi >= INF { None } else { Some(hi) };
            let lo = if lo >= INF { None } else { Some(lo) };
            (Some(a), lo, hi)
        } else {
            (None, None, None)
        }
    }

    /// Save interval mode PtrOffset info for a register
    pub fn save_interval_ptr_offset(
        &self,
        reg: Reg,
    ) -> (Option<i64>, Option<u64>, Option<i64>, Option<u32>) {
        if let NumericDomain::Interval(ref ivl) = self.domain {
            if let Some(ptr_off) = ivl.get_ptr_offset(reg) {
                return (
                    Some(ptr_off.off),
                    Some(ptr_off.var_off),
                    ptr_off.range,
                    ptr_off.id,
                );
            }
        }
        (None, None, None, None)
    }

    pub fn restore_anchor_info(&mut self, reg: Reg, spilled: &SpilledReg) {
        trace!("Restoring anchor info for {}", reg.name());
        trace!("{:?}, ", spilled);

        // Map-value pointers are self-anchored at the synthetic
        // `Reg::Zero` (interval_ops::init_map_value_ptr) and ALWAYS
        // have a defined in-value offset (0 for a fresh lookup). A
        // spill taken BEFORE the `OrNull → Value` null-check carries
        // no captured `ptr_bounds` — `PtrToMapValueOrNull` never gets
        // `init_map_value_ptr`, so `save_interval_ptr_offset` returned
        // None. The null-check propagates the slot's *type*
        // OrNull→Value, but without re-establishing the offset the
        // filled pointer had none and `interval_check_map_access` fell
        // back to the (unbounded) scalar bounds, rejecting in-bounds
        // `value[k]` loads. Default the offset to 0 here (the kernel preserves
        // PTR_TO_MAP_VALUE off/var_off/range across spill/fill, and a
        // fresh value pointer is off 0); the `Interval` arm below
        // overrides with the precise captured offset when a spill was
        // taken after pointer arithmetic.
        if matches!(
            spilled.reg_type,
            RegType::PtrToMapValue { .. } | RegType::PtrToMapValueOrNull { .. }
        ) {
            self.domain.init_map_value_ptr(reg);
        }

        use crate::analysis::machine::stack_state::PointerBounds;
        match &spilled.ptr_bounds {
            Some(PointerBounds::Zone {
                anchor,
                anchor_lo,
                anchor_hi,
                end_anchor,
                end_lo,
                end_hi,
            }) => {
                let mut touched = false;
                if let Some(anchor_reg) = anchor {
                    if let Some(hi) = anchor_hi {
                        self.domain.add_constraint(reg, *anchor_reg, *hi);
                    }
                    if let Some(lo) = anchor_lo {
                        self.domain.add_constraint(*anchor_reg, reg, *lo);
                    }
                    touched = true;
                }
                if let Some(end_reg) = end_anchor {
                    if let Some(hi) = end_hi {
                        self.domain.add_constraint(reg, *end_reg, *hi);
                    }
                    if let Some(lo) = end_lo {
                        self.domain.add_constraint(*end_reg, reg, *lo);
                    }
                    touched = true;
                }
                if touched {
                    self.domain.close();
                }
            }
            Some(PointerBounds::Interval {
                off,
                var_off,
                range,
                id,
            }) => {
                // Determine anchor from register type
                let anchor = match spilled.reg_type {
                    RegType::PtrToPacket => Some(Reg::AnchorData),
                    RegType::PtrToPacketMeta => Some(Reg::AnchorDataMeta),
                    RegType::PtrToPacketEnd => Some(Reg::AnchorDataEnd),
                    RegType::PtrToStack { .. } => Some(Reg::R10),
                    // Map-value pointers self-anchor at Reg::Zero
                    // (init_map_value_ptr). Restoring the captured
                    // off/var_off/range here overrides the off=0
                    // default set above for spills taken after
                    // in-value pointer arithmetic.
                    RegType::PtrToMapValue { .. }
                    | RegType::PtrToMapValueOrNull { .. } => Some(Reg::Zero),
                    _ => None, // fallback is None
                };

                if let (Some(anchor_reg), Some(o)) = (anchor, off) {
                    if let NumericDomain::Interval(ref mut ivl) = self.domain {
                        let v = var_off.unwrap_or(0);
                        let ptr_offset = crate::domains::interval::PtrOffset {
                            anchor: anchor_reg,
                            off: *o,
                            var_off: v,
                            range: *range,
                            // id round-trips through the spill slot so
                            // find_good_pkt_pointers-mirror propagation
                            // can match spilled pkt pointers by ID (the
                            // kernel's rule).
                            id: *id,
                            // mark_pkt_end relationship not round-tripped
                            // through spill/fill; conservative None is sound.
                            pkt_end_rel: None,
                        };

                        // Set the PtrOffset on the register
                        ivl.get_mut(reg).ptr_offset = Some(ptr_offset);
                    }
                }
            }
            None => {}
        }
    }

    /// Called on every stack access to track depth
    pub fn update_frame_depth(&mut self, off: i16) {
        if off < 0 && off > i16::MIN {
            let depth = (-off) as u16;
            self.frame_depth = self.frame_depth.max(depth);
        }
    }
}

/// Restore (or clear) a filled register's BCF symbolic expression from
/// the stack slot it was reloaded from. Mirrors the kernel's
/// `copy_register_state(&regs[dst], reg)` on fill
/// (check_stack_read_fixed_off, verifier.c:5889/5934): `bcf_expr` is
/// copied verbatim from the slot; `None` means kernel `-1`, i.e. no
/// carried expr, so the register lazy-materializes a fresh one on next
/// use. `transfer_load` clears `dst.bcf_expr` before calling `fill_at`,
/// so this re-bind on the spill-restore paths is what carries a spilled
/// scalar's expr (e.g. an `LSH` shift result) across spill/reload into a
/// later path-condition clause.
fn restore_slot_bcf_expr(state: &mut State, dst: Reg, slot_bcf: Option<u32>) {
    if let Some(idx) = dst.bcf_idx()
        && let Some(bcf) = state.bcf.as_mut()
    {
        match slot_bcf {
            Some(e) => bcf.bind_reg(idx, e),
            None => bcf.clear_reg(idx),
        }
    }
}
