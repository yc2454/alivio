// src/analysis/transfer/branch/interval_packet.rs
//
// Interval-specific packet bounds refinement.
//
// This module handles updating the interval domain's packet_size_lower_bound
// and meta_size_lower_bound when branch conditions reveal information about
// packet geometry.
//
// Example: After `if (pkt_data + 8 <= pkt_end) goto safe`, on the taken path
// we know the packet has at least 8 bytes, so we set packet_size_lower_bound = 8.
//
// Example: After `if (pkt_meta + 4 <= pkt_data) goto safe`, on the taken path
// we know the meta region has at least 4 bytes, so we set meta_size_lower_bound = 4.
//
// This logic is interval-specific because the zone domain tracks these
// relationships directly via difference constraints (pkt_end - pkt_data >= N).

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use crate::ast::CmpOp;
use crate::domains::numeric::NumericDomain;

/// Information extracted from a packet pointer comparison
struct PacketComparison {
    /// Fixed offset from the base pointer
    offset: i64,
    /// Variable offset uncertainty
    var_off: u64,
    /// Whether the offset is exactly known (no variable part)
    is_fixed: bool,
}

/// Try to extract packet data offset info from a register.
/// Returns Some if the register is pkt_data + offset.
fn get_packet_data_offset(state: &State, reg: Reg) -> Option<PacketComparison> {
    // Check if register type is PtrToPacket
    if !matches!(state.types.get(reg), RegType::PtrToPacket) {
        return None;
    }

    // Get the pointer offset info from interval state
    if let NumericDomain::Interval(ref ivl) = state.domain {
        if let Some(ptr_off) = ivl.get_ptr_offset(reg) {
            // Must be relative to AnchorData (pkt_data)
            if ptr_off.anchor == Reg::AnchorData {
                return Some(PacketComparison {
                    offset: ptr_off.off,
                    var_off: ptr_off.var_off,
                    is_fixed: ptr_off.var_off == 0,
                });
            }
        }
    }

    None
}

/// Try to extract packet meta offset info from a register.
/// Returns Some if the register is pkt_meta + offset.
fn get_packet_meta_offset(state: &State, reg: Reg) -> Option<PacketComparison> {
    // Check if register type is PtrToPacketMeta
    if !matches!(state.types.get(reg), RegType::PtrToPacketMeta) {
        return None;
    }

    // Get the pointer offset info from interval state
    if let NumericDomain::Interval(ref ivl) = state.domain {
        if let Some(ptr_off) = ivl.get_ptr_offset(reg) {
            // Must be relative to AnchorDataMeta (pkt_meta)
            if ptr_off.anchor == Reg::AnchorDataMeta {
                return Some(PacketComparison {
                    offset: ptr_off.off,
                    var_off: ptr_off.var_off,
                    is_fixed: ptr_off.var_off == 0,
                });
            }
        }
    }

    None
}

/// Check if a register represents pkt_end
fn is_packet_end(state: &State, reg: Reg) -> bool {
    matches!(state.types.get(reg), RegType::PtrToPacketEnd)
}

/// Check if a register represents pkt_data (with zero offset)
fn is_packet_data(state: &State, reg: Reg) -> bool {
    if !matches!(state.types.get(reg), RegType::PtrToPacket) {
        return false;
    }

    // Check if it has zero offset from AnchorData
    if let NumericDomain::Interval(ref ivl) = state.domain {
        if let Some(ptr_off) = ivl.get_ptr_offset(reg) {
            return ptr_off.anchor == Reg::AnchorData && ptr_off.off == 0 && ptr_off.var_off == 0;
        }
    }

    false
}

/// Refine packet bounds based on a comparison between two registers.
///
/// Called when we have a branch condition comparing packet pointers.
/// Updates packet_size_lower_bound or meta_size_lower_bound in the interval
/// state when we can prove a minimum size from the comparison.
///
/// # Arguments
/// * `state` - The state to update (should be the branch path state)
/// * `left` - Left operand of comparison
/// * `right` - Right operand of comparison
/// * `op` - The comparison operator
/// * `branch_taken` - Whether this is the taken (true) or fallthrough (false) path
pub fn refine_packet_bounds(
    state: &mut State,
    left: Reg,
    right: Reg,
    op: CmpOp,
    branch_taken: bool,
) {
    // Only applies to interval domain
    if !matches!(state.domain, NumericDomain::Interval(_)) {
        return;
    }

    // Try to refine packet data region bounds (pkt_data vs pkt_end)
    refine_data_region_bounds(state, left, right, op, branch_taken);

    // Try to refine meta region bounds (pkt_meta vs pkt_data)
    refine_meta_region_bounds(state, left, right, op, branch_taken);
}

/// Refine bounds for the packet data region [pkt_data, pkt_end)
fn refine_data_region_bounds(
    state: &mut State,
    left: Reg,
    right: Reg,
    op: CmpOp,
    branch_taken: bool,
) {
    // Look for comparisons between pkt_data+offset and pkt_end
    let (data_info, is_data_on_left, checked_reg) =
        if let Some(info) = get_packet_data_offset(state, left) {
            if is_packet_end(state, right) {
                (info, true, left)
            } else {
                return;
            }
        } else if let Some(info) = get_packet_data_offset(state, right) {
            if is_packet_end(state, left) {
                (info, false, right)
            } else {
                return;
            }
        } else {
            return;
        };

    let base_offset = data_info.offset;
    let checked_var_off = data_info.var_off;

    // Determine if this path proves packet has at least `proven_size` bytes
    // and whether it's a strict inequality (> or <) which adds 1 to the bound.
    //
    // Pattern: if (pkt_data + N OP pkt_end) goto taken
    //
    // For data_on_left (pkt_data + N OP pkt_end):
    //   ULe/SLe (<=): taken means N <= packet_size, so packet_size >= N
    //   ULt/SLt (<):  taken means N < packet_size, so packet_size >= N + 1
    //   UGt/SGt (>):  fallthrough means N <= packet_size, so packet_size >= N
    //   UGe/SGe (>=): fallthrough means N < packet_size, so packet_size >= N + 1
    //
    // For data_on_right (pkt_end OP pkt_data + N):
    //   UGe/SGe (>=): taken means packet_size >= N
    //   UGt/SGt (>):  taken means packet_size > N, so packet_size >= N + 1
    //   ULe/SLe (<=): fallthrough means packet_size >= N
    //   ULt/SLt (<):  fallthrough means packet_size > N, so packet_size >= N + 1

    // (proves_lower, is_strict) - proves packet_size >= N (or > N if strict)
    // (proves_upper, upper_strict) - proves packet_size < N (or <= N if strict)
    //
    // For data_on_left (pkt_data + N OP pkt_end):
    //   ULe taken: N <= packet_size → proves_lower, non-strict
    //   ULt taken: N < packet_size → proves_lower, strict (packet_size > N)
    //   UGt taken: N > packet_size → proves_upper (packet_size < N)
    //   UGe taken: N >= packet_size → proves_upper, strict (packet_size <= N, i.e., < N+1)
    //   UGt fallthrough: !(N > packet_size) → N <= packet_size → proves_lower, non-strict
    //   UGe fallthrough: !(N >= packet_size) → N < packet_size → proves_lower, strict
    //   ULe fallthrough: !(N <= packet_size) → N > packet_size → proves_upper
    //   ULt fallthrough: !(N < packet_size) → N >= packet_size → proves_upper, strict
    //
    // For data_on_right (pkt_end OP pkt_data + N):
    //   UGe taken: packet_size >= N → proves_lower, non-strict
    //   UGt taken: packet_size > N → proves_lower, strict
    //   ULt taken: packet_size < N → proves_upper
    //   ULe taken: packet_size <= N → proves_upper, strict (< N+1)
    //   ULe fallthrough: !(packet_size <= N) → packet_size > N → proves_lower, strict
    //   ULt fallthrough: !(packet_size < N) → packet_size >= N → proves_lower, non-strict
    //   UGe fallthrough: !(packet_size >= N) → packet_size < N → proves_upper
    //   UGt fallthrough: !(packet_size > N) → packet_size <= N → proves_upper, strict

    // Returns (proves_lower, lower_strict, proves_upper, upper_strict)
    let (proves_lower, lower_strict, proves_upper, upper_strict) = if is_data_on_left {
        match (op, branch_taken) {
            // Lower bound cases
            (CmpOp::ULe | CmpOp::SLe, true) => (true, false, false, false),
            (CmpOp::ULt | CmpOp::SLt, true) => (true, true, false, false),
            (CmpOp::UGt | CmpOp::SGt, false) => (true, false, false, false),
            (CmpOp::UGe | CmpOp::SGe, false) => (true, true, false, false),
            // Upper bound cases
            (CmpOp::UGt | CmpOp::SGt, true) => (false, false, true, false),
            (CmpOp::UGe | CmpOp::SGe, true) => (false, false, true, true),
            (CmpOp::ULe | CmpOp::SLe, false) => (false, false, true, false),
            (CmpOp::ULt | CmpOp::SLt, false) => (false, false, true, true),
            _ => (false, false, false, false),
        }
    } else {
        // pkt_end on left
        match (op, branch_taken) {
            // Lower bound cases
            (CmpOp::UGe | CmpOp::SGe, true) => (true, false, false, false),
            (CmpOp::UGt | CmpOp::SGt, true) => (true, true, false, false),
            (CmpOp::ULe | CmpOp::SLe, false) => (true, true, false, false),
            (CmpOp::ULt | CmpOp::SLt, false) => (true, false, false, false),
            // Upper bound cases
            (CmpOp::ULt | CmpOp::SLt, true) => (false, false, true, false),
            (CmpOp::ULe | CmpOp::SLe, true) => (false, false, true, true),
            (CmpOp::UGe | CmpOp::SGe, false) => (false, false, true, false),
            (CmpOp::UGt | CmpOp::SGt, false) => (false, false, true, true),
            _ => (false, false, false, false),
        }
    };

    if proves_lower {
        let proven_size = if lower_strict {
            base_offset.saturating_add(1)
        } else {
            base_offset
        };

        // For FIXED offsets only, update global packet_size_lower_bound
        if data_info.is_fixed && proven_size > 0 {
            if let NumericDomain::Interval(ref mut ivl) = state.domain {
                let current = ivl.get_packet_size_bound().unwrap_or(0);
                if proven_size as u64 > current {
                    ivl.set_packet_size_bound(proven_size as u64);
                }
            }
        }

        // For ALL successful bounds checks (including variable offset), set per-register range.
        // After proving checked_reg <= pkt_end where checked_reg is at (pkt_data + off + var_off):
        // - For any register R at (pkt_data + off' + var_off) with off' <= off:
        //   - From R, we can access (off - off') bytes
        //   - Set R.range = max(R.range, proven_size - R.off)
        if proven_size > 0 {
            propagate_packet_range(state, checked_reg, proven_size);
        }
        let _ = checked_var_off;
    }

    if proves_upper {
        // upper_strict means packet_size <= N, which is equivalent to < N+1
        let upper_exclusive = if upper_strict {
            base_offset.saturating_add(1)
        } else {
            base_offset
        };

        // Only update global upper bound for fixed offsets
        if data_info.is_fixed && upper_exclusive > 0 {
            if let NumericDomain::Interval(ref mut ivl) = state.domain {
                ivl.set_packet_size_upper_bound(upper_exclusive as u64);
            }
        }

        // Kernel `mark_pkt_end` (verifier.c): on the branch where the
        // packet pointer is proven to be out of range (`pkt > pkt_end`
        // ⇒ BEYOND, `pkt >= pkt_end` ⇒ AT), record the relationship on
        // `checked_reg` so a *duplicated* `pkt vs pkt_end` comparison can
        // be resolved statically (see `is_pkt_ptr_branch_taken` /
        // `condition_outcome`). `upper_strict` distinguishes the two:
        // strict (`>=`/`<=`) means AT, non-strict (`>`/`<`) means BEYOND.
        // Works for variable-offset pointers too — exactly the case the
        // `is_fixed` global-bound gate above skips (change_tail's R3 = udp+8).
        //
        // Applied in BOTH base and BCF mode: this is a faithful kernel
        // feature (mark_pkt_end / is_pkt_ptr_branch_taken), so BCF should
        // mirror it rather than gate it off. It is precision-INCREASING (it
        // prunes the contradictory duplicate-check path), so the expected
        // BCF effect is same-or-smaller bundles.
        let mark = if upper_strict {
            crate::domains::interval::PktEndRel::At
        } else {
            crate::domains::interval::PktEndRel::Beyond
        };
        if let NumericDomain::Interval(ref mut ivl) = state.domain {
            if let Some(po) = ivl.get_ptr_offset(checked_reg).cloned() {
                let mut new_po = po;
                new_po.pkt_end_rel = Some(mark);
                ivl.get_mut(checked_reg).ptr_offset = Some(new_po);
                if std::env::var("ZOVIA_DUMP_PKTEND").ok().as_deref() == Some("1") {
                    eprintln!("[pktend-mark] pc={} reg={:?} rel={:?} upper_strict={}",
                        state.pc, checked_reg, mark, upper_strict);
                }
            }
        }
    }
}

/// Propagate range to all packet pointer registers in the same kernel-style
/// id family as `checked_reg`.
///
/// After proving `(pkt_data + checked_off + var_off) <= pkt_end`, every
/// register that picked up the same variable offset chain (i.e. shares
/// `checked_reg.ptr_offset.id`) can be refined the same way. Mirrors the
/// kernel's `find_good_pkt_pointers`: only same-id pointers get the
/// `range` widened.
///
/// When `checked_reg` has `id == None` (no variable offset, fully fixed
/// pointer) the only register that picks up `range` is `checked_reg`
/// itself — the previous `var_off`-based grouping conflated independent
/// pointer chains and produced FALSE_ACCEPTs (e.g.
/// `verifier_direct_packet_access::id_in_regsafe_bad_access`).
fn propagate_packet_range(state: &mut State, checked_reg: Reg, proven_size: i64) {
    let checked_id = if let NumericDomain::Interval(ref ivl) = state.domain {
        ivl.get_ptr_offset(checked_reg).and_then(|po| po.id)
    } else {
        return;
    };

    let mut updates: Vec<(Reg, i64)> = Vec::new();

    if let NumericDomain::Interval(ref ivl) = state.domain {
        for reg in Reg::ALL {
            if !matches!(state.types.get(reg), RegType::PtrToPacket) {
                continue;
            }

            if let Some(ptr_off) = ivl.get_ptr_offset(reg) {
                if ptr_off.anchor != Reg::AnchorData {
                    continue;
                }
                let in_family = match (checked_id, ptr_off.id) {
                    // Variable-offset chain: only same-id members refine.
                    (Some(a), Some(b)) => a == b,
                    // No-id family (kernel `reg->id == 0`): all
                    // pkt-pointers without an id share refinement —
                    // they were never separated by variable arithmetic
                    // and therefore all alias the same anchor.
                    (None, None) => true,
                    _ => false,
                };
                if !in_family {
                    continue;
                }
                let range_for_reg = proven_size.saturating_sub(ptr_off.off);
                // range=0 is still meaningful for boundary accesses like
                // `*(reg + -N)` — keep the >= 0 guard.
                if range_for_reg >= 0 {
                    updates.push((reg, range_for_reg));
                }
            }
        }
    }

    if let NumericDomain::Interval(ref mut ivl) = state.domain {
        for (reg, range) in updates {
            if let Some(ptr_off) = ivl.get_ptr_offset(reg).cloned() {
                // -1 sentinel keeps range=0 a valid widening target.
                let current_range = ptr_off.range.unwrap_or(-1);
                if range > current_range {
                    let mut new_ptr_off = ptr_off;
                    new_ptr_off.range = Some(range);
                    ivl.get_mut(reg).ptr_offset = Some(new_ptr_off);
                }
            }
        }
    }

    // Spilled packet pointers: id now round-trips through
    // `PointerBounds::Interval`, so the kernel's same-id rule applies to
    // stack slots too (find_good_pkt_pointers iterates frames; matches
    // reg->id only). A var_off-equality approximation would grant
    // ranges across unrelated chains — kernel-UNFAITHFUL (it can prove
    // safe a reloaded-pointer load the kernel rejects).
    propagate_packet_range_to_all_frames_stack(state, checked_id, proven_size);
}

/// Propagate packet range to spilled packet pointers on ALL frames' stacks.
/// The kernel's find_good_pkt_pointers iterates all frames.
fn propagate_packet_range_to_all_frames_stack(
    state: &mut State,
    checked_id: Option<u32>,
    proven_size: i64,
) {
    for frame_idx in 0..state.num_frames() {
        let frame_level = crate::analysis::machine::frame_stack::FrameLevel::from_index(frame_idx);
        let stack = state.stack_at_mut(frame_level);

        for (_, spilled) in stack.iter_mut() {
            // Only update PtrToPacket slots
            if spilled.reg_type != RegType::PtrToPacket {
                continue;
            }

            // Check if this slot has compatible offset info
            use crate::analysis::machine::stack_state::PointerBounds;
            if let Some(PointerBounds::Interval {
                off,
                var_off: _,
                range,
                id,
            }) = &mut spilled.ptr_bounds
            {
                if let Some(o) = *off {
                    // Kernel same-id family rule (find_good_pkt_pointers):
                    // Some==Some match, or both None (never separated by
                    // variable arithmetic — alias the same anchor).
                    let in_family = match (checked_id, *id) {
                        (Some(a), Some(b)) => a == b,
                        (None, None) => true,
                        _ => false,
                    };
                    if !in_family {
                        continue;
                    }

                    // Calculate the range for this spilled pointer
                    let range_for_slot = proven_size.saturating_sub(o);
                    // Include range=0 for pointers at the boundary (offset == proven_size).
                    // This is needed for negative offset accesses like *(ptr + -N).
                    if range_for_slot >= 0 {
                        let current_range = range.unwrap_or(-1);
                        if range_for_slot > current_range {
                            *range = Some(range_for_slot);
                        }
                    }
                }
            }
        }
    }
}

/// Propagate range to all meta pointer registers with compatible offsets.
/// After proving that (pkt_meta + checked_off + var_off) <= pkt_data,
/// any register R at (pkt_meta + R.off + var_off) can access (checked_off - R.off) bytes.
fn propagate_meta_range(state: &mut State, checked_reg: Reg, proven_size: i64) {
    let checked_id = if let NumericDomain::Interval(ref ivl) = state.domain {
        ivl.get_ptr_offset(checked_reg).and_then(|po| po.id)
    } else {
        return;
    };

    let mut updates: Vec<(Reg, i64)> = Vec::new();

    if let NumericDomain::Interval(ref ivl) = state.domain {
        for reg in Reg::ALL {
            if !matches!(state.types.get(reg), RegType::PtrToPacketMeta) {
                continue;
            }

            if let Some(ptr_off) = ivl.get_ptr_offset(reg) {
                if ptr_off.anchor != Reg::AnchorDataMeta {
                    continue;
                }
                let in_family = match (checked_id, ptr_off.id) {
                    // Variable-offset chain: only same-id members refine.
                    (Some(a), Some(b)) => a == b,
                    // No-id family (kernel `reg->id == 0`): all meta
                    // pointers without an id alias the single
                    // AnchorDataMeta — they were never separated by
                    // variable arithmetic. Mirrors the data-region
                    // `propagate_packet_range` gate (same kernel
                    // `find_good_pkt_pointers` mechanism, with `data`
                    // as the region boundary instead of `data_end`).
                    (None, None) => true,
                    _ => false,
                };
                if !in_family {
                    continue;
                }
                let range_for_reg = proven_size.saturating_sub(ptr_off.off);
                if range_for_reg >= 0 {
                    updates.push((reg, range_for_reg));
                }
            }
        }
    }

    if let NumericDomain::Interval(ref mut ivl) = state.domain {
        for (reg, range) in updates {
            if let Some(ptr_off) = ivl.get_ptr_offset(reg).cloned() {
                let current_range = ptr_off.range.unwrap_or(-1);
                if range > current_range {
                    let mut new_ptr_off = ptr_off;
                    new_ptr_off.range = Some(range);
                    ivl.get_mut(reg).ptr_offset = Some(new_ptr_off);
                }
            }
        }
    }

    propagate_meta_range_to_stack(state, checked_id, proven_size);
}

/// Propagate meta range to spilled meta pointers on all stack frames.
/// Matches by kernel-style id (find_good_pkt_pointers same-id rule).
fn propagate_meta_range_to_stack(state: &mut State, checked_id: Option<u32>, proven_size: i64) {
    // Iterate over all frames and update meta pointer slots
    for frame_idx in 0..state.num_frames() {
        let frame_level = crate::analysis::machine::frame_stack::FrameLevel::from_index(frame_idx);
        let stack = state.stack_at_mut(frame_level);

        for (_, spilled) in stack.iter_mut() {
            // Only update PtrToPacketMeta slots
            if spilled.reg_type != RegType::PtrToPacketMeta {
                continue;
            }

            // Check if this slot has compatible offset info
            use crate::analysis::machine::stack_state::PointerBounds;
            if let Some(PointerBounds::Interval {
                off,
                var_off: _,
                range,
                id,
            }) = &mut spilled.ptr_bounds
            {
                if let Some(o) = *off {
                    // Kernel same-id family rule (find_good_pkt_pointers).
                    let in_family = match (checked_id, *id) {
                        (Some(a), Some(b)) => a == b,
                        (None, None) => true,
                        _ => false,
                    };
                    if !in_family {
                        continue;
                    }

                    // Calculate the range for this spilled pointer
                    let range_for_slot = proven_size.saturating_sub(o);
                    // Include range=0 for pointers at the boundary (offset == proven_size).
                    // This is needed for negative offset accesses like *(ptr + -N).
                    if range_for_slot >= 0 {
                        let current_range = range.unwrap_or(-1);
                        if range_for_slot > current_range {
                            *range = Some(range_for_slot);
                        }
                    }
                }
            }
        }
    }
}

/// Refine bounds for the meta region [pkt_meta, pkt_data)
fn refine_meta_region_bounds(
    state: &mut State,
    left: Reg,
    right: Reg,
    op: CmpOp,
    branch_taken: bool,
) {
    // Look for comparisons between pkt_meta+offset and pkt_data
    let (meta_info, is_meta_on_left) = if let Some(info) = get_packet_meta_offset(state, left) {
        if is_packet_data(state, right) {
            (info, true)
        } else {
            return;
        }
    } else if let Some(info) = get_packet_meta_offset(state, right) {
        if is_packet_data(state, left) {
            (info, false)
        } else {
            return;
        }
    } else {
        return;
    };

    // For variable offsets: we can still prove lower bounds using the fixed offset,
    // but upper bounds need the full offset (fixed + var_off).
    let base_offset = meta_info.offset;
    let max_offset = meta_info.offset.saturating_add(meta_info.var_off as i64);

    // Determine if this path proves meta region has at least `proven_size` bytes
    // and whether it's a strict inequality (> or <) which adds 1 to the bound.
    //
    // Pattern: if (pkt_meta + N OP pkt_data) goto taken
    //
    // For meta_on_left (pkt_meta + N OP pkt_data):
    //   ULe/SLe (<=): taken means N <= meta_size, so meta_size >= N
    //   ULt/SLt (<):  taken means N < meta_size, so meta_size >= N + 1
    //   UGt/SGt (>):  fallthrough means N <= meta_size, so meta_size >= N
    //   UGe/SGe (>=): fallthrough means N < meta_size, so meta_size >= N + 1
    //
    // For meta_on_right (pkt_data OP pkt_meta + N):
    //   UGe/SGe (>=): taken means meta_size >= N
    //   UGt/SGt (>):  taken means meta_size > N, so meta_size >= N + 1
    //   ULe/SLe (<=): fallthrough means meta_size >= N
    //   ULt/SLt (<):  fallthrough means meta_size > N, so meta_size >= N + 1

    // Same logic as data region, just with meta pointer and pkt_data as the boundary.
    let (proves_lower, lower_strict, proves_upper, upper_strict) = if is_meta_on_left {
        match (op, branch_taken) {
            // Lower bound cases
            (CmpOp::ULe | CmpOp::SLe, true) => (true, false, false, false),
            (CmpOp::ULt | CmpOp::SLt, true) => (true, true, false, false),
            (CmpOp::UGt | CmpOp::SGt, false) => (true, false, false, false),
            (CmpOp::UGe | CmpOp::SGe, false) => (true, true, false, false),
            // Upper bound cases
            (CmpOp::UGt | CmpOp::SGt, true) => (false, false, true, false),
            (CmpOp::UGe | CmpOp::SGe, true) => (false, false, true, true),
            (CmpOp::ULe | CmpOp::SLe, false) => (false, false, true, false),
            (CmpOp::ULt | CmpOp::SLt, false) => (false, false, true, true),
            _ => (false, false, false, false),
        }
    } else {
        // pkt_data on left
        match (op, branch_taken) {
            // Lower bound cases
            (CmpOp::UGe | CmpOp::SGe, true) => (true, false, false, false),
            (CmpOp::UGt | CmpOp::SGt, true) => (true, true, false, false),
            (CmpOp::ULe | CmpOp::SLe, false) => (true, true, false, false),
            (CmpOp::ULt | CmpOp::SLt, false) => (true, false, false, false),
            // Upper bound cases
            (CmpOp::ULt | CmpOp::SLt, true) => (false, false, true, false),
            (CmpOp::ULe | CmpOp::SLe, true) => (false, false, true, true),
            (CmpOp::UGe | CmpOp::SGe, false) => (false, false, true, false),
            (CmpOp::UGt | CmpOp::SGt, false) => (false, false, true, true),
            _ => (false, false, false, false),
        }
    };

    if proves_lower {
        let proven_size = if lower_strict {
            base_offset.saturating_add(1)
        } else {
            base_offset
        };

        if proven_size > 0 {
            if let NumericDomain::Interval(ref mut ivl) = state.domain {
                let current = ivl.get_meta_size_bound().unwrap_or(0);
                if proven_size as u64 > current {
                    ivl.set_meta_size_bound(proven_size as u64);
                }
            }
            // Propagate range to meta pointers in the same id family.
            let meta_reg = if is_meta_on_left { left } else { right };
            propagate_meta_range(state, meta_reg, proven_size);
        }
    }

    if proves_upper {
        // For upper bounds, use max_offset (includes var_off) for correctness
        let upper_exclusive = if upper_strict {
            max_offset.saturating_add(1)
        } else {
            max_offset
        };

        if upper_exclusive > 0 {
            if let NumericDomain::Interval(ref mut ivl) = state.domain {
                ivl.set_meta_size_upper_bound(upper_exclusive as u64);
            }
        }
    }
}

/// Wrapper to call refine_packet_bounds for both then and else states
pub fn refine_packet_bounds_on_branch(
    then_state: &mut State,
    else_state: &mut State,
    left: Reg,
    right: Reg,
    op: CmpOp,
) {
    refine_packet_bounds(then_state, left, right, op, true);
    refine_packet_bounds(else_state, left, right, op, false);
}
