use std::collections::HashMap;

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::ast::Program;
use crate::domains::numeric::NumericDomain;
use log::{debug, info};

use super::model::AnnotationEntry;

mod chain;
mod fact;
mod transfer;

#[allow(unused_imports)]
// Constraint must be visible in pcc for derive_fact_from_branch's return type
pub(super) use fact::{Constraint, derive_fact_from_branch};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct VerifiedEntry {
    pub left_reg: usize,
    pub right_reg: usize,
    pub bound: i64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Human-readable name for a register index, or "?" if unknown.
pub(super) fn reg_name(idx: usize) -> &'static str {
    Reg::idx_to_reg(idx).map(|r| r.name()).unwrap_or("?")
}

// ---------------------------------------------------------------------------
// Interval-state queries
// ---------------------------------------------------------------------------

pub fn distance_upper_bound(state: &State, i: Reg, j: Reg) -> Option<i64> {
    if !matches!(state.domain, NumericDomain::Interval(_)) {
        return Some(state.domain.get_distance_interval(i, j).1);
    }
    let direct = state.domain.get_distance_interval(i, j).1;
    if direct != i64::MAX {
        return Some(direct);
    }

    // Interval mode can still prove finite upper bounds against packet anchors
    // using packet-size lower bounds and per-register packet offsets.
    let ivl = state.domain.as_interval()?;
    if i == Reg::AnchorData && j == Reg::AnchorDataEnd {
        return ivl
            .get_packet_size_bound()
            .map(|n| -(i64::try_from(n).unwrap_or(i64::MAX)));
    }
    if j == Reg::AnchorDataEnd
        && let Some(pkt_lb) = ivl.get_packet_size_bound()
        && let Some(po) = ivl.get_ptr_offset(i)
        && po.anchor == Reg::AnchorData
    {
        let lb = i64::try_from(pkt_lb).unwrap_or(i64::MAX);
        return Some(po.max_offset().saturating_sub(lb));
    }

    // Map pointers: if i has PtrOffset with anchor == j (typically Zero),
    // the max distance is off + var_off (the maximum map-buffer offset).
    if let Some(po) = ivl.get_ptr_offset(i)
        && po.anchor == j
    {
        return Some(po.max_offset());
    }

    Some(direct)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Verify the proof chain in `entry` for the annotated load at `target_pc`.
///
/// Returns `Some(VerifiedEntry)` only when the chain is fully sound against
/// the interval pre-states in `explored_states`. Fail-closed: any check
/// failure returns `None` and the caller proceeds without refinement.
pub fn check_proof(
    entry: &AnnotationEntry,
    target_pc: usize,
    explored_states: &HashMap<usize, Vec<State>>,
    prog: &Program,
) -> Option<VerifiedEntry> {
    if entry.proof.is_empty() {
        return None;
    }

    debug!(
        target: "pcc",
        "[PCC] target={}: replaying {}-step proof for [{} - {} <= {}]",
        target_pc, entry.proof.len(),
        reg_name(entry.left_reg), reg_name(entry.right_reg), entry.bound,
    );

    let result = chain::replay_chain(&entry.proof, target_pc, explored_states, prog)?;

    if result.current_left != entry.left_reg || result.current_right != entry.right_reg {
        debug!(
            target: "pcc",
            "[PCC] target={}: final ({},{}) != entry ({},{}) — REJECTED",
            target_pc,
            reg_name(result.current_left), reg_name(result.current_right),
            reg_name(entry.left_reg), reg_name(entry.right_reg),
        );
        return None;
    }
    if result.accumulated_bound != entry.bound {
        debug!(
            target: "pcc",
            "[PCC] target={}: accumulated bound {} != entry bound {} — REJECTED",
            target_pc, result.accumulated_bound, entry.bound,
        );
        return None;
    }

    info!(
        target: "pcc",
        "[PCC] target={}: proof verified [{} - {} <= {}]",
        target_pc, reg_name(entry.left_reg), reg_name(entry.right_reg), entry.bound,
    );
    Some(VerifiedEntry {
        left_reg: entry.left_reg,
        right_reg: entry.right_reg,
        bound: entry.bound,
    })
}
