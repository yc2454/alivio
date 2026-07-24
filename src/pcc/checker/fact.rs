use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::ast::{CmpOp, Instr, Operand, Program, Width};
use log::debug;

use super::distance_upper_bound;

// ---------------------------------------------------------------------------
// Fact verification
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct Constraint {
    pub left_reg: usize,
    pub right_reg: usize,
    pub c: i64,
}

pub fn derive_fact_from_branch(
    pred_instr: &Instr,
    pred_pc: usize,
    succ_pc: usize,
) -> Option<Constraint> {
    let Instr::If {
        width,
        left,
        op,
        right,
        target,
    } = pred_instr
    else {
        return None;
    };
    if *width != Width::W64 {
        return None;
    }
    let branch_taken = if succ_pc == *target {
        true
    } else if succ_pc == pred_pc + 1 {
        false
    } else {
        return None;
    };

    match right {
        Operand::Reg(right_r) => {
            let (left_reg, right_reg, c) = match (*op, branch_taken) {
                (CmpOp::ULe | CmpOp::SLe, true) | (CmpOp::UGt | CmpOp::SGt, false) => {
                    (left.idx(), right_r.idx(), 0)
                }
                (CmpOp::ULt | CmpOp::SLt, true) | (CmpOp::UGe | CmpOp::SGe, false) => {
                    (left.idx(), right_r.idx(), -1)
                }
                (CmpOp::UGe | CmpOp::SGe, true) | (CmpOp::ULt | CmpOp::SLt, false) => {
                    (right_r.idx(), left.idx(), 0)
                }
                (CmpOp::UGt | CmpOp::SGt, true) | (CmpOp::ULe | CmpOp::SLe, false) => {
                    (right_r.idx(), left.idx(), -1)
                }
                _ => return None,
            };
            Some(Constraint {
                left_reg,
                right_reg,
                c,
            })
        }
        Operand::Imm(imm) => {
            // Immediate comparison: `left op imm`.
            // Constraint is `left - Zero <= c` where c depends on op and branch direction.
            let c = match (*op, branch_taken) {
                // left <= imm (fall-through of JGT, or taken JLE)
                (CmpOp::ULe | CmpOp::SLe, true) | (CmpOp::UGt | CmpOp::SGt, false) => *imm,
                // left < imm (fall-through of JGE, or taken JLT)
                (CmpOp::ULt | CmpOp::SLt, true) | (CmpOp::UGe | CmpOp::SGe, false) => {
                    imm.checked_sub(1)?
                }
                // left >= imm → Zero - left <= -imm → not a useful upper bound
                // left > imm → not a useful upper bound
                _ => return None,
            };
            Some(Constraint {
                left_reg: left.idx(),
                right_reg: Reg::Zero.idx(),
                c,
            })
        }
    }
}

/// Verify a Fact step against the interval pre-state at its PC.
///
/// Two verification paths:
/// 1. Branch-derived: the instruction at `fact_pc` is a branch and the claimed
///    constraint matches the branch condition on the fall-through edge.
/// 2. State-derived: `distance_upper_bound(state, i, j) <= c` holds directly
///    in the interval state at `fact_pc`. This is the divergence-point case
///    where zone and interval agree on the constraint.
pub(super) fn verify_fact(
    fact_pc: usize,
    left_idx: usize,
    right_idx: usize,
    c: i64,
    state: &State,
    prog: &Program,
    target_pc: usize,
) -> bool {
    let Some(i) = Reg::idx_to_reg(left_idx) else {
        return false;
    };
    let Some(j) = Reg::idx_to_reg(right_idx) else {
        return false;
    };

    // Path 1: branch-derived fact.
    // Check if the instruction at fact_pc is a branch whose fall-through condition
    // matches the claimed constraint.
    let instr = &prog.instrs[fact_pc];
    if let Some(branch_fact) = derive_fact_from_branch(instr, fact_pc, fact_pc + 1)
        && left_idx == branch_fact.left_reg
            && right_idx == branch_fact.right_reg
            && c == branch_fact.c
        {
            debug!(
                target: "pcc",
                "[PCC] target={} Fact(pc={}, {}, {}, {}): branch-derived — OK",
                target_pc, fact_pc, i.name(), j.name(), c,
            );
            return true;
        }

    // Path 2: state-derived fact.
    // The interval state at fact_pc directly proves i - j <= c.
    if let Some(ub) = distance_upper_bound(state, i, j) {
        if ub <= c {
            debug!(
                target: "pcc",
                "[PCC] target={} Fact(pc={}, {}, {}, {}): state-derived (ub={}) — OK",
                target_pc, fact_pc, i.name(), j.name(), c, ub,
            );
            return true;
        }
        debug!(
            target: "pcc",
            "[PCC] target={} Fact(pc={}, {}, {}, {}): state ub={} > {} — REJECTED",
            target_pc, fact_pc, i.name(), j.name(), c, ub, c,
        );
    } else {
        debug!(
            target: "pcc",
            "[PCC] target={} Fact(pc={}, {}, {}, {}): cannot compute distance — REJECTED",
            target_pc, fact_pc, i.name(), j.name(), c,
        );
    }
    false
}
