use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use crate::ast::{Instr, MemSize};
use crate::common::constants;
use crate::domains::dbm::{Dbm, INF};
use crate::domains::numeric::NumericDomain;
use crate::parsing::elf::BpfMapDef;

use super::super::checker::distance_upper_bound;

/// For a Load instruction, returns (base_reg, offset, size_bytes).
/// The required bound is computed by the caller via `access_anchor_and_bound`.
pub(super) fn load_info(instr: &Instr) -> Option<(Reg, i16, MemSize)> {
    let Instr::Load {
        size, base, off, ..
    } = instr
    else {
        return None;
    };
    Some((*base, *off, *size))
}

/// Determine the anchor register and required bound for a load instruction
/// based on the base register's pointer type.
///
/// Returns `(anchor_end, required_bound)` where the access is safe iff
/// `base - anchor_end <= required_bound`.
///
/// - Packet: `base - @data_end <= -(off + size)` ⟹ `base + off + size <= @data_end`
/// - Stack:  `base - R10 <= -(off + size)`       ⟹ `base + off + size <= R10 = 0`
/// - Map:    `base - Zero <= limit - off - size`  ⟹ `base + off + size <= limit`
pub(super) fn access_anchor_and_bound(
    state: &State,
    base: Reg,
    off: i64,
    size: i64,
    map_defs: &[BpfMapDef],
) -> Option<(Reg, i64)> {
    match state.types.get(base) {
        RegType::PtrToPacket => Some((Reg::AnchorDataEnd, -(off + size))),
        RegType::PtrToStack { .. } => Some((Reg::R10, -(off + size))),
        RegType::PtrToMapValue { map_idx, .. } => {
            let limit = map_defs.get(map_idx)?.value_size as i64;
            Some((Reg::Zero, limit - off - size))
        }
        _ => None,
    }
}

/// Check whether the interval domain already proves the access is safe
/// (i.e. PCC is not needed for this load).
pub(super) fn interval_already_proves_access(
    state: &State,
    base: Reg,
    off: i64,
    size: i64,
    map_defs: &[BpfMapDef],
) -> bool {
    match state.types.get(base) {
        RegType::PtrToPacket => {
            let (s, e) = state.domain.verify_packet_bounds(base, off, size);
            s && e
        }
        RegType::PtrToStack { .. } => {
            let (lo, hi) = state.domain.get_distance_interval(base, Reg::R10);
            lo != i64::MIN
                && hi != i64::MAX
                && lo + off >= constants::BPF_STACK_MIN
                && hi + off + size <= constants::BPF_STACK_MAX
        }
        RegType::PtrToMapValue { map_idx, .. } => {
            if let NumericDomain::Interval(ref ivl) = state.domain
                && let Some(po) = ivl.get_ptr_offset(base)
            {
                let min = po.min_offset() + off;
                let max = po.max_offset() + off + size;
                let limit = map_defs
                    .get(map_idx)
                    .map(|d| d.value_size as i64)
                    .unwrap_or(0);
                return min >= 0 && max <= limit;
            }
            false
        }
        _ => false,
    }
}

/// Zone upper bound for `i - j` from a DBM. Returns None if unbounded.
pub(super) fn zone_upper_bound(dbm: &Dbm, i: Reg, j: Reg) -> Option<i64> {
    let v = dbm.get(i, j);
    if v >= INF { None } else { Some(v) }
}

/// Interval upper bound for `i - j` from an interval State.
/// Wraps the checker's distance_upper_bound; returns None if unbounded.
pub(super) fn interval_upper_bound(state: &State, i: Reg, j: Reg) -> Option<i64> {
    let ub = distance_upper_bound(state, i, j)?;
    if ub == i64::MAX { None } else { Some(ub) }
}

// ---------------------------------------------------------------------------
// Same-map anchor search (Step 5b)
// ---------------------------------------------------------------------------

/// For a map-value base register, find another register `k` from the same map
/// such that `zone_upper_bound(dbm, base, k) + k.type_offset <= required`.
///
/// This enables PCC for variable map accesses: zone tracks `base - k` relationally
/// (e.g., from a branch comparing two same-map pointers), and `k.type_offset` is
/// the constant buffer offset from the interval state's type info.
///
/// Returns `(k, zone_ub(base, k))` on success.
pub(super) fn find_same_map_anchor(
    state: &State,
    dbm: &Dbm,
    base: Reg,
    base_map_idx: usize,
    required: i64,
) -> Option<(Reg, i64)> {
    for k in Reg::ALL {
        if k == base || k == Reg::Zero {
            continue;
        }
        // k must be PtrToMapValue from the same map with a known constant offset.
        if let RegType::PtrToMapValue {
            map_idx,
            offset: Some(k_off),
            ..
        } = state.types.get(k)
        {
            if map_idx != base_map_idx {
                continue;
            }
            // Check: zone_ub(base, k) + k_off <= required
            if let Some(ub) = zone_upper_bound(dbm, base, k)
                && let Some(composed) = ub.checked_add(k_off)
                && composed <= required
            {
                return Some((k, ub));
            }
        }
    }
    None
}
