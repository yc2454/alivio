use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::ast::{AluOp, Instr, Operand, Program};
use crate::domains::dbm::Dbm;
use log::debug;

use super::super::checker::derive_fact_from_branch;
use super::super::model::ProofStep;
use super::bounds::{interval_upper_bound, zone_upper_bound};

// ---------------------------------------------------------------------------
// Backward tracing (Step 6)
// ---------------------------------------------------------------------------

/// A backward-traced step before it is reversed into the forward chain.
///
/// During backward tracing the generator walks from the target load toward the divergence
/// point, calling [`backward_transfer`] at each instruction to invert the instruction's
/// semantics: given the post-state constraint, what must the pre-state constraint be?
///
/// Each `BackwardStep` stores the forward-Transfer data (i.e. the same `delta` and
/// register mapping that would appear in a [`ProofStep::Transfer`]) even though it was
/// discovered by walking backward. When the divergence point is found, the accumulated
/// `BackwardStep`s are reversed into [`ProofStep::Transfer`] entries in forward order.
///
/// Field names follow the forward Transfer convention:
/// `pre_left_reg/pre_right_reg` is the constraint pair **before** the instruction,
/// `post_left_reg/post_right_reg` is the pair **after** it, and `delta` is the
/// forward bound shift (`post_bound = pre_bound + delta`).
pub(super) struct BackwardStep {
    pub(super) pc: usize,
    pub(super) pre_left_reg: usize,
    pub(super) pre_right_reg: usize,
    pub(super) post_left_reg: usize,
    pub(super) post_right_reg: usize,
    pub(super) delta: i64,
    /// Human-readable description of why `delta` is what it is (see `backward_transfer`).
    pub(super) hint: Option<String>,
}

/// Trace backward from `target_pc` to find the divergence point where the
/// interval state agrees with the zone on the tracked constraint.
///
/// Returns `Some((guard_pc, guard_i, guard_j, fact_c, steps))` on success,
/// where `steps` is in **forward** order (ready for the certificate).
/// Returns `None` if tracing fails (unsupported instruction, etc.).
pub(super) fn backward_trace(
    prog: &Program,
    zone_dbms: &[Dbm],
    interval_states: &[State],
    target_pc: usize,
    target_i: Reg,
    target_j: Reg,
    target_bound: i64,
) -> Option<(usize, usize, usize, i64, Vec<ProofStep>)> {
    let mut cur_i = target_i;
    let mut cur_j = target_j;
    let mut cur_bound = target_bound;
    let mut backward_steps: Vec<BackwardStep> = Vec::new();

    // Walk backward from target_pc - 1 (the instruction before the load).
    let mut pc = target_pc.checked_sub(1)?;

    loop {
        // First, compute the backward transfer through the instruction at this PC.
        // This tells us what the constraint looks like BEFORE this instruction.
        let instr = &prog.instrs[pc];
        let (prev_i, prev_j, delta, hint) =
            backward_transfer(instr, cur_i, cur_j, zone_dbms, pc)?;
        let pre_bound = cur_bound.checked_sub(delta)?;

        // Record this as a backward step (instruction transforms constraint).
        backward_steps.push(BackwardStep {
            pc,
            pre_left_reg: prev_i.idx(),
            pre_right_reg: prev_j.idx(),
            post_left_reg: cur_i.idx(),
            post_right_reg: cur_j.idx(),
            delta,
            hint,
        });

        // Now check: does the interval agree on the PRE-instruction constraint?
        // Two paths: (1) state-derived, (2) branch-derived.
        if pc < interval_states.len() {
            // Path 1: State-derived — interval state directly proves the constraint.
            let mut fact_found = false;
            let mut fact_c = 0i64;

            if let Some(ivl_ub) = interval_upper_bound(&interval_states[pc], prev_i, prev_j)
                && ivl_ub <= pre_bound {
                    fact_found = true;
                    fact_c = ivl_ub;
                }

            // Path 2: Branch-derived — if the instruction at this PC is a branch
            // whose fall-through condition matches the tracked constraint pair,
            // derive the guard from the branch semantics. This handles the case
            // where a branch refines a variable AFTER a variable add (e.g., stack
            // variable-offset access where zone's closure captures the refinement
            // but the interval's var_off is not retroactively tightened).
            if !fact_found
                && let Some(branch_fact) =
                    derive_fact_from_branch(instr, pc, pc + 1)
                    && branch_fact.left_reg == prev_i.idx()
                        && branch_fact.right_reg == prev_j.idx()
                        && branch_fact.c <= pre_bound
                    {
                        fact_found = true;
                        fact_c = branch_fact.c;
                    }

            if fact_found {
                let mut proof = Vec::with_capacity(1 + backward_steps.len());
                proof.push(ProofStep::Fact {
                    pc,
                    left_reg: prev_i.idx(),
                    right_reg: prev_j.idx(),
                    c: fact_c,
                });

                // Reverse backward steps into forward order as Transfer steps
                for bs in backward_steps.into_iter().rev() {
                    proof.push(ProofStep::Transfer {
                        pc: bs.pc,
                        pre_left_reg: bs.pre_left_reg,
                        pre_right_reg: bs.pre_right_reg,
                        post_left_reg: bs.post_left_reg,
                        post_right_reg: bs.post_right_reg,
                        delta: bs.delta,
                        hint: bs.hint,
                    });
                }

                return Some((pc, prev_i.idx(), prev_j.idx(), fact_c, proof));
            }
        }

        // If we've reached pc 0 without finding the divergence, give up.
        if pc == 0 {
            debug!(
                target: "pcc-gen",
                "[PCC-GEN] target={}: backward trace reached pc=0 without finding divergence",
                target_pc,
            );
            return None;
        }

        cur_i = prev_i;
        cur_j = prev_j;
        cur_bound = pre_bound;
        pc -= 1;
    }
}

/// Compute the backward transfer through a single instruction.
///
/// Given that after the instruction at `pc`, the constraint `cur_i - cur_j <= cur_bound`
/// holds (the post-state), returns `(prev_i, prev_j, delta)` such that the pre-state
/// constraint `prev_i - prev_j <= cur_bound - delta` is a valid backward implication.
///
/// Equivalently, `delta` is the *forward* bound shift: when `prev_i - prev_j <= pre_bound`
/// holds before the instruction, then `cur_i - cur_j <= pre_bound + delta` holds after it.
/// The caller computes `pre_bound = cur_bound - delta`.
///
/// The derivations for each supported case (let `L = cur_i`, `R = cur_j`):
///
/// - **`mov dst, src`** (`cur_i == dst`):
///   Post: `dst - R <= b`. Since `dst_post == src_pre`, pre: `src - R <= b`. `delta = 0`.
///
/// - **`add dst, imm`** (`cur_i == dst`):
///   Post: `(dst_old+imm) - R <= b`  ⟺  `dst_old - R <= b - imm`. `delta = imm`.
///
/// - **`add dst, imm`** (`cur_j == dst`):
///   Post: `L - (dst_old+imm) <= b`  ⟺  `L - dst_old <= b + imm`. `delta = -imm`.
///
/// - **`add dst, src_reg`** (`cur_i == dst`):
///   Post: `(dst_old+src) - R <= b`  ⟺  `dst_old - R <= b - src`.
///   The tightest conservative pre-bound uses `src <= ub(src)` (worst case: src is largest):
///   `dst_old - R <= b - ub(src)`. `delta = ub(src)` from the zone DBM at `pc`.
///
/// - **`add dst, src_reg`** (`cur_j == dst`):
///   Post: `L - (dst_old+src) <= b`  ⟺  `L - dst_old <= b + src`.
///   The tightest conservative pre-bound uses `src >= lb(src)` (worst case: src is smallest):
///   `L - dst_old <= b + lb(src)`. `delta = -lb(src)` from the zone DBM at `pc`.
///
/// - **Passthrough** (`dst` ∉ {`cur_i`, `cur_j`}): constraint unchanged. `delta = 0`.
///
/// Returns `None` for unsupported instructions that write to a tracked register in a way
/// the generator cannot invert.
fn backward_transfer(
    instr: &Instr,
    cur_i: Reg,
    cur_j: Reg,
    zone_dbms: &[Dbm],
    pc: usize,
) -> Option<(Reg, Reg, i64, Option<String>)> {
    match instr {
        // mov dst, src  →  dst_post = src_pre.
        // If cur_i == dst, the value now in dst came from src before the move.
        // Pre-constraint: src - cur_j <= b (same bound, delta = 0).
        // Symmetric for cur_j.
        Instr::Alu {
            op: AluOp::Mov,
            dst,
            src: Operand::Reg(src),
            ..
        } => {
            let prev_i = if cur_i == *dst { *src } else { cur_i };
            let prev_j = if cur_j == *dst { *src } else { cur_j };
            // Build a hint only when a register rename actually happens.
            let hint = if cur_i == *dst && cur_j != *dst {
                Some(format!(
                    "{} = {}  [{} renamed to {}; tracking {} now]",
                    dst.name(),
                    src.name(),
                    src.name(),
                    dst.name(),
                    dst.name(),
                ))
            } else if cur_j == *dst && cur_i != *dst {
                Some(format!(
                    "{} = {}  [{} renamed to {}; tracking {} now]",
                    dst.name(),
                    src.name(),
                    src.name(),
                    dst.name(),
                    dst.name(),
                ))
            } else {
                None // passthrough (dst ∉ {cur_i, cur_j})
            };
            Some((prev_i, prev_j, 0, hint))
        }

        // add dst, imm  →  dst_post = dst_pre + imm.
        // cur_i == dst: (dst_pre+imm) - cur_j <= b  ⟺  dst_pre - cur_j <= b - imm.
        //   delta = imm (pre_bound = cur_bound - imm).
        // cur_j == dst: cur_i - (dst_pre+imm) <= b  ⟺  cur_i - dst_pre <= b + imm.
        //   delta = -imm (pre_bound = cur_bound + imm).
        Instr::Alu {
            op: AluOp::Add,
            dst,
            src: Operand::Imm(imm),
            ..
        } => {
            if *dst == cur_i {
                // Left side shifts: L += imm  →  L-R bound increases by imm.
                let hint = if *imm >= 0 {
                    Some(format!("{} += {}", dst.name(), imm))
                } else {
                    Some(format!("{} -= {}", dst.name(), -imm))
                };
                Some((cur_i, cur_j, *imm, hint))
            } else if *dst == cur_j {
                // Right side shifts: R += imm  →  L-R bound decreases by imm.
                let hint = if *imm >= 0 {
                    Some(format!(
                        "{} += {}  (right side grows; {}-{} tightens by {})",
                        dst.name(),
                        imm,
                        cur_i.name(),
                        cur_j.name(),
                        imm,
                    ))
                } else {
                    Some(format!(
                        "{} -= {}  (right side shrinks; {}-{} relaxes by {})",
                        dst.name(),
                        -imm,
                        cur_i.name(),
                        cur_j.name(),
                        -imm,
                    ))
                };
                Some((cur_i, cur_j, -(*imm), hint))
            } else {
                // Passthrough: dst doesn't affect the tracked pair.
                Some((cur_i, cur_j, 0, None))
            }
        }

        // add dst, src_reg  →  dst_post = dst_pre + src_reg.
        // cur_i == dst: (dst_pre+src) - cur_j <= b  ⟺  dst_pre - cur_j <= b - src.
        //   Worst case (largest src): src = ub(src).  Pre-bound = b - ub(src). delta = ub(src).
        // cur_j == dst: cur_i - (dst_pre+src) <= b  ⟺  cur_i - dst_pre <= b + src.
        //   Worst case (smallest src): src = lb(src). Pre-bound = b + lb(src). delta = -lb(src).
        //   lb(src) = -ub(Zero - src) = -zone_upper_bound(dbm, Zero, src).
        Instr::Alu {
            op: AluOp::Add,
            dst,
            src: Operand::Reg(src),
            ..
        } => {
            if *dst == cur_i && cur_j == *src {
                // Pivot: add dst, src where we're tracking dst-src.
                // After: dst_new = dst_old + src. So dst_new - src = dst_old.
                // The pre-constraint is dst_old - Zero <= b (delta=0).
                let hint = Some(format!(
                    "{} += {}  [pivot: {}-{} → {}-Zero, delta=0]",
                    dst.name(),
                    src.name(),
                    cur_i.name(),
                    cur_j.name(),
                    cur_i.name(),
                ));
                Some((cur_i, Reg::Zero, 0, hint))
            } else if *dst == cur_i {
                let dbm = zone_dbms.get(pc)?;
                let src_ub = zone_upper_bound(dbm, *src, Reg::Zero)?;
                // Left side increases by at most src_ub.
                let hint = Some(format!(
                    "{} += {}  ({} <= {}, worst case)",
                    dst.name(),
                    src.name(),
                    src.name(),
                    src_ub,
                ));
                Some((cur_i, cur_j, src_ub, hint))
            } else if *dst == cur_j {
                let dbm = zone_dbms.get(pc)?;
                let src_lb = {
                    // lb(src) = -ub(Zero - src)
                    let neg_lb = zone_upper_bound(dbm, Reg::Zero, *src)?;
                    -neg_lb
                };
                // Right side increases by at least src_lb.
                let hint = Some(format!(
                    "{} += {}  ({} >= {}, worst case)",
                    dst.name(),
                    src.name(),
                    src.name(),
                    src_lb,
                ));
                Some((cur_i, cur_j, -src_lb, hint))
            } else {
                Some((cur_i, cur_j, 0, None))
            }
        }

        // Any other instruction: check if it writes to a tracked register.
        _ => {
            if instr_writes(instr, cur_i) || instr_writes(instr, cur_j) {
                // Unsupported: instruction modifies tracked register
                None
            } else {
                // Passthrough: instruction does not touch cur_i or cur_j.
                Some((cur_i, cur_j, 0, None))
            }
        }
    }
}

/// Quick soundness check for a backward-trace proof: verifies that each Transfer
/// step's delta is compatible with the interval state at its PC. Returns false if
/// any `add dst, src_reg` Transfer uses a delta smaller than the interval's upper
/// bound of `src_reg` (the checker would reject it).
pub(super) fn transfer_deltas_sound(
    proof: &[ProofStep],
    prog: &Program,
    interval_states: &[State],
) -> bool {
    for step in proof {
        let ProofStep::Transfer {
            pc,
            pre_left_reg,
            pre_right_reg: _,
            delta,
            ..
        } = step
        else {
            continue;
        };
        if *pc >= prog.instrs.len() {
            continue;
        }
        let instr = &prog.instrs[*pc];
        // Check `add dst, src_reg` where dst == pre_left: delta must >= interval_ub(src)
        if let Instr::Alu {
            op: AluOp::Add,
            dst,
            src: Operand::Reg(src),
            ..
        } = instr
            && dst.idx() == *pre_left_reg
                && let Some(state) = interval_states.get(*pc) {
                    let (_, src_max) = state.domain.get_interval(*src);
                    if src_max != i64::MAX && *delta < src_max {
                        return false;
                    }
                }
    }
    true
}

/// Returns true if `instr` writes to the given register.
pub(super) fn instr_writes(instr: &Instr, reg: Reg) -> bool {
    match instr {
        Instr::Alu { dst, .. }
        | Instr::Endian { dst, .. }
        | Instr::Load { dst, .. }
        | Instr::LoadMap { dst, .. } => *dst == reg,
        Instr::Call { .. } | Instr::LoadPacket { .. } => {
            matches!(reg, Reg::R0 | Reg::R1 | Reg::R2 | Reg::R3 | Reg::R4 | Reg::R5)
        }
        _ => false,
    }
}
