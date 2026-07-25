use std::collections::HashMap;

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::ast::{AluOp, Instr, Operand, Program, Width};
use crate::domains::numeric::NumericDomain;
use log::debug;

use super::super::model::ProofStep;
use super::fact::verify_fact;
use super::reg_name;
use super::transfer::{instr_writes_reg, verify_transfer};

// ---------------------------------------------------------------------------
// Internal proof-check state (separate from verifier State)
// ---------------------------------------------------------------------------

/// Tracks progress through a single proof chain during replay verification.
///
/// This is **not** the verifier's abstract state — it is purely proof-chain bookkeeping,
/// kept entirely separate from [`State`] to make it clear that the checker only reads
/// interval states and never modifies them.
///
/// **Invariant:** after processing step `k` of the chain,
/// `current_left - current_right <= accumulated_bound` is the bound derivable
/// from all steps seen so far. The chain starts from the Fact's `c` (the base
/// constraint independently verified against the interval state), adjusted by each
/// Derive's offset, and accumulated by each Transfer's `delta`. At the end of the
/// chain, `accumulated_bound` must equal `entry.bound`.
pub(super) struct ProofCheckState {
    /// The left register of the currently tracked constraint pair.
    pub(super) current_left: usize,
    /// The right register of the currently tracked constraint pair.
    pub(super) current_right: usize,
    /// Running upper bound: `current_left - current_right <= accumulated_bound`.
    pub(super) accumulated_bound: i64,
}

// ---------------------------------------------------------------------------
// Replay verification
// ---------------------------------------------------------------------------

/// Verify a proof chain (possibly containing Compose steps) and return the
/// resulting proof-check state. This is the recursive core shared by both
/// the top-level `check_proof` and Compose sub-proof verification.
///
/// The chain must begin with a [`ProofStep::Fact`] and be followed by zero or more
/// [`ProofStep::Derive`] and [`ProofStep::Transfer`] steps. Replay maintains the running
/// invariant: `current_left - current_right <= accumulated_bound`, starting from the
/// Fact's independently verified base case, adjusted by each Derive, and accumulated
/// by each Transfer's `delta`.
///
/// Fail-closed: returns `None` if any check fails or a required state is missing.
pub(super) fn replay_chain(
    proof: &[ProofStep],
    target_pc: usize,
    explored_states: &HashMap<usize, Vec<State>>,
    prog: &Program,
) -> Option<ProofCheckState> {
    if proof.is_empty() {
        return None;
    }

    // A single Compose step is a valid proof by itself
    if proof.len() == 1
        && let ProofStep::Compose { left, right, via } = &proof[0]
    {
        return verify_compose(left, right, *via, target_pc, explored_states, prog);
    }

    // Step 0: Verify Fact (must be proof[0])
    let ProofStep::Fact {
        pc: fact_pc,
        left_reg: fact_left,
        right_reg: fact_right,
        c: fact_c,
    } = &proof[0]
    else {
        debug!(target: "pcc", "[PCC] target={}: proof[0] is not Fact — REJECTED", target_pc);
        return None;
    };

    let fact_state = get_unique_state(explored_states, *fact_pc, target_pc)?;
    if !matches!(fact_state.domain, NumericDomain::Interval(_)) {
        return None;
    }

    if !verify_fact(
        *fact_pc,
        *fact_left,
        *fact_right,
        *fact_c,
        fact_state,
        prog,
        target_pc,
    ) {
        return None;
    }

    let mut pcs = ProofCheckState {
        current_left: *fact_left,
        current_right: *fact_right,
        accumulated_bound: *fact_c,
    };

    // Steps 1..n
    for (sidx, step) in proof.iter().enumerate().skip(1) {
        match step {
            ProofStep::Fact { .. } => {
                debug!(
                    target: "pcc",
                    "[PCC] target={} step {}: unexpected Fact after first position — REJECTED",
                    target_pc, sidx,
                );
                return None;
            }
            ProofStep::Derive {
                pc_start,
                pc_end,
                source_reg,
                target_reg,
                offset,
            } => {
                if *source_reg != pcs.current_left {
                    debug!(
                        target: "pcc",
                        "[PCC] target={} step {}: Derive source {} != current_left {} — REJECTED",
                        target_pc, sidx, reg_name(*source_reg), reg_name(pcs.current_left),
                    );
                    return None;
                }
                if !verify_derive(
                    *pc_start,
                    *pc_end,
                    *source_reg,
                    *target_reg,
                    *offset,
                    prog,
                    target_pc,
                ) {
                    return None;
                }
                pcs.current_left = *target_reg;
                pcs.current_right = 0;
                pcs.accumulated_bound = pcs.accumulated_bound.checked_sub(*offset)?;
                debug!(
                    target: "pcc",
                    "[PCC] target={} Derive(pc={}→{}, {}={}{:+}) — bound now {}",
                    target_pc, pc_start, pc_end,
                    reg_name(*source_reg), reg_name(*target_reg),
                    *offset, pcs.accumulated_bound,
                );
            }
            ProofStep::Transfer {
                pc: step_pc,
                pre_left_reg,
                pre_right_reg,
                post_left_reg,
                post_right_reg,
                delta,
                ..
            } => {
                if *pre_left_reg != pcs.current_left || *pre_right_reg != pcs.current_right {
                    debug!(
                        target: "pcc",
                        "[PCC] target={} step {}: chain disconnected ({},{}) != ({},{}) — REJECTED",
                        target_pc, sidx,
                        reg_name(*pre_left_reg), reg_name(*pre_right_reg),
                        reg_name(pcs.current_left), reg_name(pcs.current_right),
                    );
                    return None;
                }
                let step_state = get_unique_state(explored_states, *step_pc, target_pc)?;
                if *step_pc >= prog.instrs.len() {
                    return None;
                }
                let instr = &prog.instrs[*step_pc];
                if !verify_transfer(
                    *step_pc,
                    *pre_left_reg,
                    *pre_right_reg,
                    *post_left_reg,
                    *post_right_reg,
                    *delta,
                    step_state,
                    instr,
                    target_pc,
                ) {
                    return None;
                }
                pcs.current_left = *post_left_reg;
                pcs.current_right = *post_right_reg;
                pcs.accumulated_bound = pcs.accumulated_bound.checked_add(*delta)?;
            }
            ProofStep::Compose { left, right, via } => {
                let compose_result =
                    verify_compose(left, right, *via, target_pc, explored_states, prog)?;
                pcs.current_left = compose_result.current_left;
                pcs.current_right = compose_result.current_right;
                pcs.accumulated_bound = pcs
                    .accumulated_bound
                    .checked_add(compose_result.accumulated_bound)?;
            }
        }
    }

    Some(pcs)
}

/// Verify a Compose step by recursively verifying left and right sub-proofs
/// and checking that they compose through the intermediate register `via`.
fn verify_compose(
    left: &[ProofStep],
    right: &[ProofStep],
    via: usize,
    target_pc: usize,
    explored_states: &HashMap<usize, Vec<State>>,
    prog: &Program,
) -> Option<ProofCheckState> {
    debug!(
        target: "pcc",
        "[PCC] target={}: verifying Compose via {}",
        target_pc, reg_name(via),
    );

    // Verify left sub-proof: should prove L - via <= a
    let left_result = replay_chain(left, target_pc, explored_states, prog)?;
    if left_result.current_right != via {
        debug!(
            target: "pcc",
            "[PCC] target={}: Compose left output right {} != via {} — REJECTED",
            target_pc, reg_name(left_result.current_right), reg_name(via),
        );
        return None;
    }

    // Verify right sub-proof: should prove via - R <= b
    let right_result = replay_chain(right, target_pc, explored_states, prog)?;
    if right_result.current_left != via {
        debug!(
            target: "pcc",
            "[PCC] target={}: Compose right output left {} != via {} — REJECTED",
            target_pc, reg_name(right_result.current_left), reg_name(via),
        );
        return None;
    }

    // Compose: L - R <= a + b
    let composed_bound = left_result
        .accumulated_bound
        .checked_add(right_result.accumulated_bound)?;

    debug!(
        target: "pcc",
        "[PCC] target={}: Compose via {}: {} + {} = {}",
        target_pc, reg_name(via),
        left_result.accumulated_bound, right_result.accumulated_bound, composed_bound,
    );

    Some(ProofCheckState {
        current_left: left_result.current_left,
        current_right: right_result.current_right,
        accumulated_bound: composed_bound,
    })
}

/// Verify a Derive step by replaying instructions from `pc_start` to `pc_end`
/// and confirming they establish `source_reg = target_reg + offset`.
///
/// The verification tracks how `source_reg` relates to `target_reg` through
/// assignments and constant additions:
///   - `mov source, target` establishes `source = target + 0`
///   - `add source, imm` shifts the offset: `source = target + (prev_offset + imm)`
fn verify_derive(
    pc_start: usize,
    pc_end: usize,
    source_reg: usize,
    target_reg: usize,
    claimed_offset: i64,
    prog: &Program,
    target_pc: usize,
) -> bool {
    if pc_start > pc_end || pc_end >= prog.instrs.len() {
        debug!(target: "pcc", "[PCC] target={}: Derive pc range {}..{} invalid — REJECTED", target_pc, pc_start, pc_end);
        return false;
    }

    let Some(source) = Reg::idx_to_reg(source_reg) else {
        return false;
    };
    let Some(target) = Reg::idx_to_reg(target_reg) else {
        return false;
    };

    // Track: after replaying instructions, source should be target + accumulated_offset
    let mut accumulated_offset: i64 = 0;
    let mut linked = false; // have we seen the assignment that links source to target?

    for pc in pc_start..=pc_end {
        let instr = &prog.instrs[pc];
        match instr {
            // mov source, target — establishes the link
            Instr::Alu {
                width: Width::W64,
                op: AluOp::Mov,
                dst,
                src: Operand::Reg(src_r),
            } if *dst == source && *src_r == target => {
                accumulated_offset = 0;
                linked = true;
            }
            // add source, imm — shifts the offset
            Instr::Alu {
                width: Width::W64,
                op: AluOp::Add,
                dst,
                src: Operand::Imm(imm),
            } if *dst == source && linked => {
                accumulated_offset += *imm;
            }
            // Any instruction that overwrites source after link breaks it
            _ if linked && instr_writes_reg(instr, source) => {
                debug!(
                    target: "pcc",
                    "[PCC] target={}: Derive pc {}: {} overwritten after link — REJECTED",
                    target_pc, pc, reg_name(source_reg),
                );
                return false;
            }
            // Any instruction that overwrites target after link breaks it
            _ if linked && instr_writes_reg(instr, target) => {
                debug!(
                    target: "pcc",
                    "[PCC] target={}: Derive pc {}: {} overwritten after link — REJECTED",
                    target_pc, pc, reg_name(target_reg),
                );
                return false;
            }
            _ => {} // passthrough — doesn't affect the relationship
        }
    }

    if !linked {
        debug!(
            target: "pcc",
            "[PCC] target={}: Derive: no link from {} to {} in pcs {}..{} — REJECTED",
            target_pc, reg_name(source_reg), reg_name(target_reg), pc_start, pc_end,
        );
        return false;
    }

    if accumulated_offset != claimed_offset {
        debug!(
            target: "pcc",
            "[PCC] target={}: Derive: computed offset {} != claimed {} — REJECTED",
            target_pc, accumulated_offset, claimed_offset,
        );
        return false;
    }

    debug!(
        target: "pcc",
        "[PCC] target={} Derive({}→{}, {}={}{:+}) — OK",
        target_pc, pc_start, pc_end,
        reg_name(source_reg), reg_name(target_reg), claimed_offset,
    );
    true
}

/// Look up the unique interval pre-state at a PC from explored_states.
/// Fail-closed: returns None if missing or if multiple states exist (non-straightline).
fn get_unique_state(
    explored_states: &HashMap<usize, Vec<State>>,
    pc: usize,
    target_pc: usize,
) -> Option<&State> {
    let states = explored_states.get(&pc)?;
    if states.len() != 1 {
        debug!(
            target: "pcc",
            "[PCC] target={}: expected 1 state at pc={}, found {} — REJECTED (non-straightline?)",
            target_pc, pc, states.len(),
        );
        return None;
    }
    Some(&states[0])
}
