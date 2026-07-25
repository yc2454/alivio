// src/analysis/transfer/alu/helpers.rs

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use crate::ast::{Operand, Width};
use crate::common::constants;
use crate::refinement::symbolic::{RegBounds, SymbolicState};

/// Build a [`RegBounds`] snapshot for `reg` from the current numeric
/// domain. Used by BCF transfer-function mirrors to materialize register
/// expressions in kernel-shape (with the right `fit_u32` / `fit_s32`
/// fast-paths).
///
/// Callers typically snapshot **before** the abstract-domain op runs (for
/// the dst/src expressions that go INTO the ALU op) and then take a
/// second snapshot **after** the op (for the post-narrowness flags
/// `op_u32` / `op_s32`). Mirrors kernel's pattern at verifier.c:16178-16181.
pub(crate) fn bcf_reg_bounds(state: &State, reg: Reg) -> RegBounds {
    let (smin, smax) = state.domain.get_interval(reg);
    let (umin, umax) = state.domain.get_u64_bounds(reg);
    let (mut s32_min, mut s32_max) = state.domain.get_s32_bounds(reg);
    let (mut u32_min, mut u32_max) = state.domain.get_u32_bounds(reg);
    let const_val = state.domain.get_fixed_value(reg).map(|v| v as u64);
    // Tighten the 32-bit bounds from the 64-bit interval when the
    // abstract domain hasn't propagated them itself (Zone mode doesn't
    // always sync s32/u32 fields for pointer regs). The kernel's
    // bcf_reg_expr cares about fit_u32/fit_s32 to choose 32- vs 64-bit
    // BCF ops; failing to tighten here forces us into 64-bit ops even
    // when the value provably fits, which causes structural divergence
    // from the kernel's DAG.
    if (s32_min, s32_max) == (i32::MIN, i32::MAX)
        && smin >= i32::MIN as i64
        && smax <= i32::MAX as i64
    {
        s32_min = smin as i32;
        s32_max = smax as i32;
    }
    if (u32_min, u32_max) == (0, u32::MAX) && smin >= 0 && smax <= u32::MAX as i64 {
        u32_min = smin as u32;
        u32_max = smax as u32;
    }
    RegBounds {
        const_val,
        smin,
        smax,
        umin,
        umax,
        s32_min,
        s32_max,
        u32_min,
        u32_max,
    }
}

/// Shared BCF mirror for binary scalar ALU ops the kernel routes
/// through `bcf_alu` (verifier.c:15166) — currently OR/XOR/MUL, all of
/// which are in `is_safe_to_compute_dst_reg_range`'s safe set so the
/// kernel always builds `BCF_BV | op` over `[reg_expr(dst),
/// reg_expr(src)]` (+ kernel-shape zext/sext). Byte-for-byte the same
/// block `handle_and` uses (the b35e055-proven template); factored so
/// the missing-build handlers don't each re-derive it. Callers MUST
/// snapshot `dst_bounds_pre` (and `src_bounds_pre` for the reg case)
/// BEFORE the abstract-domain op runs, exactly like `handle_and`.
///
/// Mirrors kernel `bcf_alu`'s `tnum_is_const(dst_reg->var_off) →
/// bcf_expr = -1; return 0` early bail-out (verifier.c:15220-15223) via
/// `SymbolicState::clear_reg_if_const`: when the post-op value is a
/// known constant, the cached expr is cleared and no chain is built —
/// the next `reg_expr` call emits a pure `bcf_val(K)` literal.
pub(crate) fn emit_bcf_alu_binop(
    state: &mut State,
    op: u8,
    width: Width,
    dst: Reg,
    src: &Operand,
    dst_bounds_pre: &RegBounds,
    src_bounds_pre: Option<&RegBounds>,
) {
    let dst_bounds_post = bcf_reg_bounds(state, dst);
    let op_u32 = dst_bounds_post.fit_u32();
    let op_s32 = dst_bounds_post.fit_s32();
    let alu32_class = width == Width::W32;
    let alu32 = alu32_class || op_u32 || op_s32;
    let bits: u16 = if alu32 { 32 } else { 64 };

    let Some(d) = dst.bcf_idx() else { return };
    if let Some(bcf) = state.bcf.as_mut()
        && bcf.clear_reg_if_const(d, &dst_bounds_post)
    {
        return;
    }
    let extend_back = |bcf: &mut SymbolicState, alu_result: u32| -> u32 {
        if alu32 || op_u32 {
            bcf.add_extend(false, 32, 64, alu_result)
        } else if op_s32 {
            bcf.add_extend(true, 32, 64, alu_result)
        } else {
            alu_result
        }
    };
    match src {
        Operand::Imm(c) => {
            if let Some(bcf) = state.bcf.as_mut() {
                let dst_expr = bcf.reg_expr(d, dst_bounds_pre, alu32);
                let c_val = if width == Width::W32 {
                    (*c as u32) as u64
                } else {
                    *c as u64
                };
                let c_expr = bcf.add_val(c_val, alu32);
                let alu_result = bcf.add_alu(op, dst_expr, c_expr, bits);
                let final_idx = extend_back(bcf, alu_result);
                bcf.bind_reg(d, final_idx);
            }
        }
        Operand::Reg(r) => {
            let si = r.bcf_idx();
            if let (Some(bcf), Some(si), Some(sb)) = (state.bcf.as_mut(), si, src_bounds_pre) {
                let dst_expr = bcf.reg_expr(d, dst_bounds_pre, alu32);
                let src_expr = bcf.reg_expr(si, sb, alu32);
                let alu_result = bcf.add_alu(op, dst_expr, src_expr, bits);
                let final_idx = extend_back(bcf, alu_result);
                bcf.bind_reg(d, final_idx);
            } else if let Some(bcf) = state.bcf.as_mut() {
                bcf.clear_reg(d);
            }
        }
    }
}

/// Unary variant of [`emit_bcf_alu_binop`] for BPF_NEG (the only
/// unary ALU op the kernel routes through `bcf_alu`; NEG is in
/// `is_safe_to_compute_dst_reg_range`'s safe set). Mirrors the
/// kernel's `unary` path: `code = BCF_BV | op`, vlen=1, args=[dst],
/// + kernel-shape zext/sext. Caller snapshots `dst_bounds_pre`
/// before the abstract op.
pub(crate) fn emit_bcf_alu_unary(
    state: &mut State,
    op: u8,
    width: Width,
    dst: Reg,
    dst_bounds_pre: &RegBounds,
) {
    let dst_bounds_post = bcf_reg_bounds(state, dst);
    let op_u32 = dst_bounds_post.fit_u32();
    let op_s32 = dst_bounds_post.fit_s32();
    let alu32_class = width == Width::W32;
    let alu32 = alu32_class || op_u32 || op_s32;
    let bits: u16 = if alu32 { 32 } else { 64 };

    let Some(d) = dst.bcf_idx() else { return };
    if let Some(bcf) = state.bcf.as_mut() {
        if bcf.clear_reg_if_const(d, &dst_bounds_post) {
            return;
        }
        let dst_expr = bcf.reg_expr(d, dst_bounds_pre, alu32);
        let alu_result = bcf.add_unary(op, dst_expr, bits);
        let final_idx = if alu32 || op_u32 {
            bcf.add_extend(false, 32, 64, alu_result)
        } else if op_s32 {
            bcf.add_extend(true, 32, 64, alu_result)
        } else {
            alu_result
        };
        bcf.bind_reg(d, final_idx);
    }
}

/// Tightens the active numeric domain's bounds using information from
/// the register's Tnum. Dispatches through `state.domain` so it applies
/// to whichever domain is in use — in kernel-mode that's the Interval
/// domain, NOT Zone/DBM (the old `_to_dbm` name was a misnomer).
pub(crate) fn sync_tnum_to_bounds(state: &mut State, reg: Reg) {
    let tnum = state.get_tnum(reg);
    let tnum_min = tnum.min_value();
    let tnum_max = tnum.max_value();

    // Only sync if tnum bounds fit in signed i64 range
    if tnum_max <= i64::MAX as u64 {
        let (dbm_lo, dbm_hi) = state.domain.get_interval(reg);

        // Tighten lower bound
        if dbm_lo == i64::MIN || (tnum_min as i64) > dbm_lo {
            state.domain.assume_ge_imm(reg, tnum_min as i64);
        }

        // Tighten upper bound
        if dbm_hi == i64::MAX || (tnum_max as i64) < dbm_hi {
            state.domain.assume_le_imm(reg, tnum_max as i64);
        }
    }
}

/// Check pointer bounds after arithmetic operations.
pub(crate) fn check_ptr_bounds(state: &mut State, reg: Reg) {
    match state.types.get(reg) {
        RegType::PtrToPacket => {
            let packet_start_reg_op = crate::analysis::machine::reg::REG_ENV
                .all()
                .iter()
                .find(|&&r| matches!(state.types.get(r), RegType::PtrToPacket));
            if let Some(packet_start_reg) = packet_start_reg_op {
                let (_, hi) = state.domain.get_distance_interval(reg, *packet_start_reg);
                if hi != i64::MAX && hi > constants::MAX_PACKET_OFF {
                    state.domain.forget(reg);
                }
            }
        }
        RegType::PtrToPacketMeta => {
            let packet_start_reg_op = crate::analysis::machine::reg::REG_ENV
                .all()
                .iter()
                .find(|&&r| matches!(state.types.get(r), RegType::PtrToPacketMeta));
            if let Some(packet_start_reg) = packet_start_reg_op {
                let (_, hi) = state.domain.get_distance_interval(reg, *packet_start_reg);
                if hi != i64::MAX && hi > constants::MAX_PACKET_OFF {
                    state.domain.forget(reg);
                }
            }
        }
        _ => {}
    }
}
