use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::ast::{AluOp, Instr, Operand};
use log::debug;

use super::distance_upper_bound;
use super::reg_name;

// ---------------------------------------------------------------------------
// Transfer verification
// ---------------------------------------------------------------------------

/// Verify a Transfer step against the interval pre-state and instruction at its PC.
///
/// A Transfer step claims: if `pre_left - pre_right <= b` holds in the pre-state of
/// the instruction at `step_pc`, then `post_left - post_right <= b + delta` holds in
/// the post-state. This function checks whether the claimed `(post_left, post_right, delta)`
/// is a sound consequence of the instruction's semantics.
///
/// Let `L = pre_left`, `R = pre_right`. The four supported cases and their soundness
/// arguments (all using the fact that `L - R <= b` holds before the instruction):
///
/// - **`add dst, imm`** (`dst == L`, `post_left == L`, `post_right == R`):
///   `(L+imm) - R = (L-R) + imm <= b + imm`. Requires `delta == imm` exactly.
///
/// - **`add dst, imm`** (`dst == R`, `post_left == L`, `post_right == R`):
///   `L - (R+imm) = (L-R) - imm <= b - imm`. Requires `delta == -imm` exactly.
///
/// - **`add dst, src_reg`** (`dst == L`, `post_left == L`, `post_right == R`):
///   `(L+src) - R = (L-R) + src`. Since `src <= ub(src)` (from the interval pre-state),
///   the result is `<= b + ub(src)`. Requires `delta >= ub(src)`; the generator uses
///   the tightest value (`delta == ub(src)`), but the checker accepts any sound overestimate.
///
/// - **`add dst, src_reg`** (`dst == R`, `post_left == L`, `post_right == R`):
///   `L - (R+src) = (L-R) - src`. Since `src >= lb(src)`, the result is `<= b - lb(src)`.
///   Requires `delta >= -lb(src)`.
///
/// - **`mov dst, src`** (`src == L`, `post_left == dst.idx()`, `post_right == R`):
///   After the move, `dst` holds the old value of `L`. The constraint `L - R <= b` becomes
///   `dst - R <= b` with the same bound. Requires `delta == 0` and `post_left == dst.idx()`.
///
/// - **Passthrough** (`dst ∉ {L, R}`): the constraint registers are untouched.
///   Requires `post_left == pre_left`, `post_right == pre_right`, `delta == 0`.
///
/// - **Unsupported write to `L` or `R`**: returns `false` (chain fails, fail-closed).
pub(super) fn verify_transfer(
    step_pc: usize,
    pre_left: usize,
    pre_right: usize,
    post_left: usize,
    post_right: usize,
    delta: i64,
    state: &State,
    instr: &Instr,
    target_pc: usize,
) -> bool {
    match instr {
        // mov dst, src (register)
        Instr::Alu {
            op: AluOp::Mov,
            dst,
            src: Operand::Reg(src),
            ..
        } => {
            // After mov dst, src: dst gets src's old value.
            // If pre_left tracks src, then post_left should be dst (src's value is now in dst).
            // If pre_right tracks src, symmetric.
            // If neither pre_left nor pre_right is dst, passthrough.
            let expected_post_left = if pre_left == src.idx()
                && *dst != Reg::idx_to_reg(pre_right).unwrap_or(Reg::Zero)
            {
                dst.idx()
            } else {
                pre_left
            };
            let expected_post_right = if pre_right == src.idx()
                && *dst != Reg::idx_to_reg(pre_left).unwrap_or(Reg::Zero)
            {
                dst.idx()
            } else {
                pre_right
            };

            // If dst overwrites a tracked register and we're not substituting, fail.
            if (*dst == Reg::idx_to_reg(pre_left).unwrap_or(Reg::Zero)
                || *dst == Reg::idx_to_reg(pre_right).unwrap_or(Reg::Zero))
                && post_left == pre_left
                && post_right == pre_right
                && pre_left != src.idx()
                && pre_right != src.idx()
            {
                debug!(
                    target: "pcc",
                    "[PCC] target={} Transfer(pc={}) mov {}<-{}: dst overwrites tracked reg — REJECTED",
                    target_pc, step_pc, dst.name(), src.name(),
                );
                return false;
            }

            if post_left != expected_post_left || post_right != expected_post_right || delta != 0 {
                debug!(
                    target: "pcc",
                    "[PCC] target={} Transfer(pc={}) mov: expected ({},{},0) got ({},{},{}) — REJECTED",
                    target_pc, step_pc,
                    reg_name(expected_post_left), reg_name(expected_post_right),
                    reg_name(post_left), reg_name(post_right), delta,
                );
                return false;
            }
            true
        }

        // add dst, imm
        Instr::Alu {
            op: AluOp::Add,
            dst,
            src: Operand::Imm(imm),
            ..
        } => {
            let di = dst.idx();
            if di == pre_left && pre_left == post_left && pre_right == post_right {
                // dst is the i-side: bound shifts by +imm
                if delta != *imm {
                    debug!(
                        target: "pcc",
                        "[PCC] target={} Transfer(pc={}) add imm: delta={} != imm={} — REJECTED",
                        target_pc, step_pc, delta, imm,
                    );
                    return false;
                }
                true
            } else if di == pre_right && pre_left == post_left && pre_right == post_right {
                // dst is the j-side: bound shifts by -imm
                if delta != -(*imm) {
                    debug!(
                        target: "pcc",
                        "[PCC] target={} Transfer(pc={}) add imm j-side: delta={} != -{} — REJECTED",
                        target_pc, step_pc, delta, imm,
                    );
                    return false;
                }
                true
            } else if di != pre_left && di != pre_right {
                // dst doesn't touch tracked registers: passthrough
                if pre_left != post_left || pre_right != post_right || delta != 0 {
                    debug!(
                        target: "pcc",
                        "[PCC] target={} Transfer(pc={}) add imm passthrough mismatch — REJECTED",
                        target_pc, step_pc,
                    );
                    return false;
                }
                true
            } else {
                debug!(
                    target: "pcc",
                    "[PCC] target={} Transfer(pc={}) add imm: register pair mismatch — REJECTED",
                    target_pc, step_pc,
                );
                false
            }
        }

        // add dst, src_reg
        Instr::Alu {
            op: AluOp::Add,
            dst,
            src: Operand::Reg(src),
            ..
        } => {
            let di = dst.idx();
            if di == pre_left && pre_left == post_left && pre_right == post_right {
                // dst is the i-side: bound shifts by ub(src) from interval state
                let (_src_min, src_max) = state.domain.get_interval(*src);
                if delta < src_max {
                    debug!(
                        target: "pcc",
                        "[PCC] target={} Transfer(pc={}) add reg: delta={} < ub(src)={} — REJECTED",
                        target_pc, step_pc, delta, src_max,
                    );
                    return false;
                }
                true
            } else if di == pre_right && pre_left == post_left && pre_right == post_right {
                // dst is the j-side: bound shifts by -lb(src)
                let (src_min, _src_max) = state.domain.get_interval(*src);
                if delta < -src_min {
                    debug!(
                        target: "pcc",
                        "[PCC] target={} Transfer(pc={}) add reg j-side: delta={} < -lb(src)={} — REJECTED",
                        target_pc, step_pc, delta, -src_min,
                    );
                    return false;
                }
                true
            } else if src.idx() == pre_left
                && di != pre_left
                && di != pre_right
                && post_left == di
                && post_right == pre_right
            {
                // Absorb case: add dst, src_reg where src_reg == pre_left.
                // Pre: src_reg - pre_right <= b. Post: dst_new = dst_old + src_reg.
                // dst_new - pre_right = dst_old + (src_reg - pre_right) <= dst_old_ub + b.
                // delta must be >= ub(dst - pre_right) from the interval pre-state.
                let pre_right_reg = Reg::idx_to_reg(pre_right).unwrap_or(Reg::Zero);
                let dst_ub = distance_upper_bound(state, *dst, pre_right_reg)
                    .filter(|&ub| ub != i64::MAX);
                let ok = dst_ub.is_some_and(|ub| delta >= ub);
                debug!(
                    target: "pcc",
                    "[PCC] target={} Transfer(pc={}) add reg absorb: {} += {}, dst_ub={:?}, delta={} — {}",
                    target_pc, step_pc, dst.name(), src.name(), dst_ub, delta,
                    if ok { "OK" } else { "REJECTED" },
                );
                ok
            } else if di == pre_left
                && pre_right == Reg::Zero.idx()
                && post_left == pre_left
                && post_right == src.idx()
                && delta == 0
            {
                // Pivot: add dst, src where pre tracks dst-Zero, post tracks dst-src, delta=0.
                // Sound: dst_new - src = dst_old = dst_old - Zero.
                debug!(
                    target: "pcc",
                    "[PCC] target={} Transfer(pc={}) add reg pivot: {} += {}, {}-Zero → {}-{} — OK",
                    target_pc, step_pc, dst.name(), src.name(), dst.name(), dst.name(), src.name(),
                );
                true
            } else if di != pre_left && di != pre_right {
                // Passthrough
                if pre_left != post_left || pre_right != post_right || delta != 0 {
                    return false;
                }
                true
            } else {
                false
            }
        }

        // Instructions that don't write to tracked registers: passthrough
        _ => {
            // Check if this instruction writes to pre_left or pre_right
            let fl = Reg::idx_to_reg(pre_left).unwrap_or(Reg::Zero);
            let fr = Reg::idx_to_reg(pre_right).unwrap_or(Reg::Zero);

            if instr_writes_reg(instr, fl) || instr_writes_reg(instr, fr) {
                debug!(
                    target: "pcc",
                    "[PCC] target={} Transfer(pc={}) unsupported write to tracked reg — REJECTED",
                    target_pc, step_pc,
                );
                return false;
            }

            // Passthrough: constraint unchanged
            if pre_left != post_left || pre_right != post_right || delta != 0 {
                debug!(
                    target: "pcc",
                    "[PCC] target={} Transfer(pc={}) passthrough mismatch — REJECTED",
                    target_pc, step_pc,
                );
                return false;
            }
            true
        }
    }
}

/// Returns true if `instr` writes to the given register.
pub(super) fn instr_writes_reg(instr: &Instr, reg: Reg) -> bool {
    match instr {
        Instr::Alu { dst, .. }
        | Instr::Endian { dst, .. }
        | Instr::Load { dst, .. }
        | Instr::LoadMap { dst, .. } => *dst == reg,
        Instr::Call { .. } | Instr::LoadPacket { .. } => {
            // Function calls clobber R0-R5
            matches!(
                reg,
                Reg::R0 | Reg::R1 | Reg::R2 | Reg::R3 | Reg::R4 | Reg::R5
            )
        }
        _ => false,
    }
}
