use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use log::info;

use super::checker::VerifiedEntry;

/// Apply a single verified PCC fact to a successor state.
///
/// Supports two strategies based on the anchor relationship:
///
/// **Cross-anchor** (packet: `j == @data_end`, `po.anchor == @data`):
///   The bound `reg_i - @data_end <= c` means `|c|` bytes are accessible from
///   `reg_i`. Sets `po.range = |c|`.
///
/// **Same-anchor** (stack: `j == R10`, map: `j == Zero`):
///   The bound `reg_i - anchor <= c` means `max_offset(reg_i) <= c`. Since
///   `max_offset = off + var_off`, we tighten `var_off <= c - off`. This lets
///   the interval's access check (which reads `off + var_off`) succeed.
fn apply_verified_fact(
    succ_state: &mut State,
    i_idx: usize,
    j_idx: usize,
    c: i64,
    succ_pc: usize,
) {
    let Some(i) = Reg::idx_to_reg(i_idx) else {
        return;
    };
    let Some(j) = Reg::idx_to_reg(j_idx) else {
        return;
    };
    let Some(ivl) = succ_state.domain.as_interval_mut() else {
        return;
    };
    let Some(po) = ivl.get_ptr_offset(i).copied() else {
        return;
    };

    if j == Reg::AnchorDataEnd && po.anchor == Reg::AnchorData {
        // Cross-anchor (packet): set po.range.
        // The PCC bound `reg_i - data_end <= c` means `data_end - reg_i >= |c|`,
        // so |c| bytes are accessible from reg_i.  Unlike the branch handler's
        // `proven_size` (which is relative to @data), the PCC bound is already
        // relative to the register value, so we must NOT subtract po.off.
        let proven_range = (-c).max(0);
        let reg = ivl.get_mut(i);
        if let Some(ref mut ptr_off) = reg.ptr_offset {
            ptr_off.range = Some(ptr_off.range.unwrap_or(proven_range).max(proven_range));
            info!(
                target: "pcc",
                "[PCC] pc={}: strengthened {}.range to {} (packet accessible: {} bytes from register)",
                succ_pc,
                i.name(),
                ptr_off.range.unwrap(),
                proven_range,
            );
        }
    } else if j == po.anchor {
        // Same-anchor (stack: j==R10, map: j==Zero).
        // Cert says: i - anchor <= c, so max_offset(i) <= c,
        // i.e. off + var_off <= c, so var_off <= c - off.
        let new_var_off_ub = (c - po.off).max(0) as u64;
        let reg = ivl.get_mut(i);
        if let Some(ref mut ptr_off) = reg.ptr_offset {
            let old_var_off = ptr_off.var_off;
            ptr_off.var_off = ptr_off.var_off.min(new_var_off_ub);
            info!(
                target: "pcc",
                "[PCC] pc={}: tightened {}.var_off from {} to {} (anchor={}, cert bound={})",
                succ_pc,
                i.name(),
                old_var_off,
                ptr_off.var_off,
                j.name(),
                c,
            );
        }
    } else {
        // Same-map transitive: j is a PtrToMapValue from the same map as i,
        // with a known buffer offset. Cert says i - j <= c, so:
        //   i.off + i.var_off <= c + j.off + j.var_off
        //   i.var_off <= c + (j.off + j.var_off) - i.off
        let i_type = succ_state.types.get(i);
        let j_type = succ_state.types.get(j);
        if let (
            RegType::PtrToMapValue { map_idx: i_map, .. },
            RegType::PtrToMapValue { map_idx: j_map, .. },
        ) = (i_type, j_type)
            && i_map == j_map
                && let Some(j_po) = ivl.get_ptr_offset(j).copied() {
                    let j_max_off = j_po.off + j_po.var_off as i64;
                    let new_var_off_ub = (c + j_max_off - po.off).max(0) as u64;
                    let reg = ivl.get_mut(i);
                    if let Some(ref mut ptr_off) = reg.ptr_offset {
                        let old_var_off = ptr_off.var_off;
                        ptr_off.var_off = ptr_off.var_off.min(new_var_off_ub);
                        info!(
                            target: "pcc",
                            "[PCC] pc={}: tightened {}.var_off from {} to {} \
                             (same-map reg={}, cert bound={})",
                            succ_pc, i.name(), old_var_off, ptr_off.var_off, j.name(), c,
                        );
                    }
                }
    }
}

/// Applies verifier-produced PCC facts to successor state.
///
/// Injection is intentionally narrow and fail-closed.
pub fn apply_verified_refinements(succ_state: &mut State, facts: &[VerifiedEntry]) {
    if facts.is_empty() {
        return;
    }
    let succ_pc = succ_state.pc;
    for fact in facts {
        apply_verified_fact(
            succ_state,
            fact.left_reg,
            fact.right_reg,
            fact.bound,
            succ_pc,
        );
    }
}
