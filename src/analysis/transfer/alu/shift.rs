// src/analysis/transfer/alu/shift.rs

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::ast::{Operand, Width};
use crate::domains::tnum::Tnum;

use super::helpers::{bcf_reg_bounds, sync_tnum_to_bounds};

/// Kernel `is_safe_to_compute_dst_reg_range` (verifier.c:15064): a
/// shift's dst range is only computable when the amount is a constant
/// strictly less than the operation bit-width (32 or 64). "Shifts
/// greater than 31 or 63 are undefined. This includes shifts by a
/// negative number." When not safe, `adjust_scalar_min_max_vals`
/// (verifier.c:15089) does `__mark_reg_unknown(dst); return 0;` — a
/// fully-unknown 64-bit scalar, with NO `zext_32_to_64` (it returns
/// before that). A negative immediate / out-of-range const has a huge
/// `umax_value`, so the unsigned `>= bit-width` test covers it.
///
/// Returns `true` (and applies the kernel `__mark_reg_unknown` shape +
/// clears the BCF expr, mirroring `bcf_alu` being gated on the same
/// `is_safe` predicate) iff the shift amount is a known constant whose
/// value is `>= bit-width`. Callers must early-return when it returns
/// true. A non-const amount is handled by each op's existing
/// conservative reg-source path (the kernel also `__mark_reg_unknown`s
/// there — `src_is_const` is false). Without this, a masked-amount
/// computation models the UB `1 << 32` as `1 << 0 = 1` and accepts a
/// later OOB access (FALSE-ACCEPT:
/// verifier_bounds::shift_with_oversized_count_operand).
fn mark_unknown_if_oversized_shift(
    state: &mut State,
    width: Width,
    dst: Reg,
    src: &Operand,
) -> bool {
    let bw: u64 = if width == Width::W32 { 32 } else { 64 };
    let const_amt: Option<u64> = match src {
        Operand::Imm(k) => Some(*k as u64),
        Operand::Reg(sr) => state.get_tnum(*sr).const_value(),
    };
    let Some(amt) = const_amt else { return false };
    if amt < bw {
        return false;
    }
    // kernel __mark_reg_unknown: fully-unknown 64-bit (no zext on the
    // not-safe path) for both W32 and W64.
    state.domain.forget(dst);
    state.set_tnum(dst, Tnum::unknown());
    sync_tnum_to_bounds(state, dst);
    if let Some(d) = dst.bcf_idx()
        && let Some(bcf) = state.bcf.as_mut()
    {
        bcf.clear_reg(d);
    }
    true
}

pub(crate) fn handle_shr(state: &mut State, width: Width, dst: Reg, src: &Operand) {
    if mark_unknown_if_oversized_shift(state, width, dst, src) {
        return;
    }
    // Snapshot dst's BCF bounds before the abstract op runs. Right shifts
    // only narrow, so fit_u32/fit_s32 from pre-op bounds is a safe
    // (sometimes-overly-conservative) approximation of the post-op
    // narrowness the kernel uses at verifier.c:16179-16180. The previously-
    // cached dst BCF expression (if any) is used directly via reg_expr.
    let dst_bounds_pre = bcf_reg_bounds(state, dst);

    match src {
        Operand::Imm(k) => {
            let k = *k as u32;
            let shift_amount = if width == Width::W32 {
                k & 0x1F
            } else {
                k & 0x3F
            };

            let (old_lo, old_hi) = state.domain.get_interval(dst);
            let old_tnum = state.get_tnum(dst);
            state.domain.forget(dst);

            if width == Width::W32 {
                let truncated_tnum = old_tnum.trunc32();
                let dbm_lo = if old_lo >= 0 && old_hi <= u32::MAX as i64 {
                    old_lo as u64
                } else {
                    0
                };
                let dbm_hi = if old_lo >= 0 && old_hi <= u32::MAX as i64 {
                    old_hi as u64
                } else {
                    u32::MAX as u64
                };

                let trunc_lo = truncated_tnum.min_value().max(dbm_lo);
                let trunc_hi = truncated_tnum.max_value().min(dbm_hi);

                let new_lo = (trunc_lo >> shift_amount) as i64;
                let new_hi = (trunc_hi >> shift_amount) as i64;

                state.domain.assume_ge_imm(dst, new_lo);
                state.domain.assume_le_imm(dst, new_hi);

                let new_tnum = truncated_tnum.shr_imm(shift_amount as u64);
                state.set_tnum(dst, new_tnum);
            } else {
                state.domain.assume_ge_imm(dst, 0);

                // A logical right shift by k caps the result at
                // `u64::MAX >> k` UNCONDITIONALLY — independent of the
                // input range. For k=32 this is 0xffffffff, the bound the
                // `r <<= 32; r >>= 32` zero-extend idiom relies on. When
                // the input range is unknown (full), this is the ONLY
                // thing keeping umax finite; the kernel always sets
                // umax_value = umax >> k (<= this cap). The cap must apply
                // even to a full-range input (e.g. after `<<= 32` widened
                // it); otherwise umax stays u64::MAX and `bcf_bound_reg`
                // never emits the ULE(reg,0xffffffff) the kernel emits.
                if shift_amount > 0 {
                    let cap = u64::MAX >> shift_amount;
                    if cap <= i64::MAX as u64 {
                        state.domain.assume_le_imm(dst, cap as i64);
                    }
                }
                // Tighten further when the input range is known and
                // non-negative (an exact shift of a known interval).
                if old_lo != i64::MIN && old_hi != i64::MAX && old_lo >= 0 {
                    let new_lo = (old_lo as u64 >> shift_amount) as i64;
                    let new_hi = (old_hi as u64 >> shift_amount) as i64;
                    state.domain.assume_ge_imm(dst, new_lo);
                    state.domain.assume_le_imm(dst, new_hi);
                }

                let new_tnum = old_tnum.shr_imm(shift_amount as u64);
                state.set_tnum(dst, new_tnum);
            }
        }
        Operand::Reg(_) => {
            state.domain.forget(dst);
            state.domain.assume_ge_imm(dst, 0);

            if width == Width::W32 {
                state.domain.assume_le_imm(dst, u32::MAX as i64);
                state.set_tnum(dst, Tnum::u32_unknown());
            } else {
                state.set_tnum(dst, Tnum::unknown());
            }
        }
    }

    sync_tnum_to_bounds(state, dst);

    // --- BCF symbolic mirror. Mirrors kernel `bcf_alu` (verifier.c:15139)
    //     with kernel-shape width discipline. For W32 RSH or for W64 RSH
    //     where dst fits in u32, emits RSH_32(reg_expr32, k_32) then ZEXT
    //     to 64. Reg-source path stays conservative (clear) for now. ---
    if let (Some(d), Operand::Imm(k)) = (dst.bcf_idx(), src) {
        let dst_bounds_post = bcf_reg_bounds(state, dst);
        if let Some(bcf) = state.bcf.as_mut() {
            // Kernel-mirror bcf_alu early bail-out (verifier.c:15220-15223).
            if bcf.clear_reg_if_const(d, &dst_bounds_post) {
                return;
            }
            let shift_amount = if width == Width::W32 {
                (*k as u32) & 0x1F
            } else {
                (*k as u32) & 0x3F
            };
            let op_u32 = dst_bounds_pre.fit_u32();
            let op_s32 = dst_bounds_pre.fit_s32();
            let alu32_class = width == Width::W32;
            let alu32 = alu32_class || op_u32 || op_s32;
            let bits: u16 = if alu32 { 32 } else { 64 };

            let dst_expr = bcf.reg_expr(d, &dst_bounds_pre, alu32);
            let k_expr = bcf.add_val(shift_amount as u64, alu32);
            let alu_result = bcf.add_alu(crate::refinement::bcf::BPF_RSH, dst_expr, k_expr, bits);

            let final_idx = if alu32 || op_u32 {
                bcf.add_extend(false, 32, 64, alu_result)
            } else if op_s32 {
                bcf.add_extend(true, 32, 64, alu_result)
            } else {
                alu_result
            };
            bcf.bind_reg(d, final_idx);
        }
    } else if let (Some(d), Operand::Reg(sr)) = (dst.bcf_idx(), src) {
        // Const-valued register shift == immediate shift. Kernel
        // is_safe_to_compute_dst_reg_range (verifier.c:16050): shift
        // is safe (→ bcf_alu builds the expr) iff the amount reg is
        // const and < bitness; otherwise __mark_reg_unknown clears.
        // Mirrors handle_shl's 71fbb43 gate.
        let src_const = state.get_tnum(*sr).const_value();
        if let Some(c) = src_const {
            let shift_amount = if width == Width::W32 {
                (c as u32) & 0x1F
            } else {
                (c as u32) & 0x3F
            };
            let dst_bounds_post = bcf_reg_bounds(state, dst);
            if let Some(bcf) = state.bcf.as_mut() {
                // Kernel-mirror bcf_alu early bail-out (verifier.c:15220-15223).
                if bcf.clear_reg_if_const(d, &dst_bounds_post) {
                    return;
                }
                let op_u32 = dst_bounds_pre.fit_u32();
                let op_s32 = dst_bounds_pre.fit_s32();
                let alu32_class = width == Width::W32;
                let alu32 = alu32_class || op_u32 || op_s32;
                let bits: u16 = if alu32 { 32 } else { 64 };

                let dst_expr = bcf.reg_expr(d, &dst_bounds_pre, alu32);
                let k_expr = bcf.add_val(shift_amount as u64, alu32);
                let alu_result =
                    bcf.add_alu(crate::refinement::bcf::BPF_RSH, dst_expr, k_expr, bits);
                let final_idx = if alu32 || op_u32 {
                    bcf.add_extend(false, 32, 64, alu_result)
                } else if op_s32 {
                    bcf.add_extend(true, 32, 64, alu_result)
                } else {
                    alu_result
                };
                bcf.bind_reg(d, final_idx);
            }
        } else if let Some(bcf) = state.bcf.as_mut() {
            // Variable shift amount — kernel emits no RSH expr here.
            bcf.clear_reg(d);
        }
    } else if let Some(d) = dst.bcf_idx()
        && let Some(bcf) = state.bcf.as_mut()
    {
        bcf.clear_reg(d);
    }
}

/// Abstract-domain (interval + tnum) update for a left shift by a *known*
/// amount. Mirrors the kernel `scalar_min_max_lsh` / `scalar32_min_max_lsh`
/// (verifier.c:15871/15919). The kernel reaches this same code for both an
/// immediate shift and a `BPF_X` shift whose amount register holds a known
/// constant (it constructs a fake src_reg with umin==umax==imm), so the two
/// cases must produce identical bounds. `shift_amount` is already masked to
/// the operation width (`& 0x1F` for W32, `& 0x3F` for W64).
fn lsh_domain_known(state: &mut State, width: Width, dst: Reg, shift_amount: u32) {
    let (old_lo, old_hi) = state.domain.get_interval(dst);
    let old_tnum = state.get_tnum(dst);
    state.domain.forget(dst);

    if width == Width::W32 {
        let truncated_tnum = old_tnum.trunc32();
        let dbm_lo = if old_lo >= 0 && old_hi <= u32::MAX as i64 {
            old_lo as u64
        } else {
            0
        };
        let dbm_hi = if old_lo >= 0 && old_hi <= u32::MAX as i64 {
            old_hi as u64
        } else {
            u32::MAX as u64
        };

        let trunc_lo = truncated_tnum.min_value().max(dbm_lo);
        let trunc_hi = truncated_tnum.max_value().min(dbm_hi);

        if shift_amount < 32 {
            let max_safe = u32::MAX as u64 >> shift_amount;
            if trunc_hi <= max_safe {
                let new_lo = ((trunc_lo << shift_amount) & 0xFFFFFFFF) as i64;
                let new_hi = ((trunc_hi << shift_amount) & 0xFFFFFFFF) as i64;
                state.domain.assume_ge_imm(dst, new_lo);
                state.domain.assume_le_imm(dst, new_hi);
            } else {
                state.domain.assume_ge_imm(dst, 0);
                state.domain.assume_le_imm(dst, u32::MAX as i64);
            }
        } else {
            state.domain.assume_eq_imm(dst, 0);
        }

        let new_tnum = truncated_tnum.shl_imm(shift_amount as u64).trunc32();
        state.set_tnum(dst, new_tnum);
    } else {
        if shift_amount == 32 {
            if old_lo != i64::MIN && old_hi != i64::MAX {
                let (lo, hi) = (old_lo, old_hi);
                if lo >= i32::MIN as i64 && hi <= i32::MAX as i64 {
                    state.domain.assume_ge_imm(dst, lo << 32);
                    state.domain.assume_le_imm(dst, hi << 32);
                }
            }
        } else if old_lo != i64::MIN && old_hi != i64::MAX {
            let (lo, hi) = (old_lo, old_hi);
            if lo >= 0 && shift_amount < 64 {
                let max_safe: i64 = if shift_amount == 63 {
                    0
                } else {
                    i64::MAX >> shift_amount
                };
                if hi <= max_safe {
                    state.domain.assume_ge_imm(dst, lo << shift_amount);
                    state.domain.assume_le_imm(dst, hi << shift_amount);
                }
            }
        }

        let new_tnum = old_tnum.shl_imm(shift_amount as u64);
        state.set_tnum(dst, new_tnum);
    }

    sync_tnum_to_bounds(state, dst);
}

pub(crate) fn handle_shl(state: &mut State, width: Width, dst: Reg, src: &Operand) {
    if mark_unknown_if_oversized_shift(state, width, dst, src) {
        return;
    }
    // Snapshot dst's BCF bounds before the abstract op runs. The kernel
    // (verifier.c:16096 + 16179) computes op_u32/op_s32 as the AND of
    // pre- and post-op fit_*, because LSH can widen a u32-bounded value
    // out of u32 range (e.g. `r3 <<= 32` for r3 ∈ [5, 4095] yields
    // r3 ∈ [5<<32, 4095<<32] which no longer fits u32). Capture pre-op
    // bounds here; we'll snapshot post-op bounds after the domain
    // update.
    let dst_bounds_pre = bcf_reg_bounds(state, dst);

    match src {
        Operand::Imm(k) => {
            let k = *k as u32;
            let shift_amount = if width == Width::W32 {
                k & 0x1F
            } else {
                k & 0x3F
            };
            lsh_domain_known(state, width, dst, shift_amount);
        }
        Operand::Reg(sr) => {
            // Kernel `scalar*_min_max_lsh` takes the shift register's
            // umin/umax. When that register holds a known constant the
            // kernel produces umin==umax==c, i.e. the *identical* bounds
            // as an immediate shift by c (verifier.c:15871/15919 via the
            // fake src_reg in adjust_scalar_min_max_vals). Mirror that:
            // const amount reg ⇒ same bounded math as the Imm path.
            // A variable (non-const) amount stays conservative — the
            // BCF symbolic mirror below also clears the expr there, and
            // narrowing the const-only gate matches the prior shift
            // commits (1b7ed62 / 71fbb43).
            if let Some(c) = state.get_tnum(*sr).const_value() {
                let shift_amount = if width == Width::W32 {
                    (c as u32) & 0x1F
                } else {
                    (c as u32) & 0x3F
                };
                lsh_domain_known(state, width, dst, shift_amount);
            } else {
                state.domain.forget(dst);

                if width == Width::W32 {
                    state.domain.assume_ge_imm(dst, 0);
                    state.domain.assume_le_imm(dst, u32::MAX as i64);
                    state.set_tnum(dst, Tnum::u32_unknown());
                } else {
                    state.set_tnum(dst, Tnum::unknown());
                }

                sync_tnum_to_bounds(state, dst);
            }
        }
    }

    // --- BCF symbolic mirror. Mirrors kernel `bcf_alu` (verifier.c:15139)
    //     with the kernel's pre+post fit_* width-discipline for shifts
    //     (verifier.c:16096 + 16179). For W64 SHL where the dst was bounded
    //     within u32 pre-op but pushed beyond u32 post-op (e.g. the
    //     `r3 <<= 32; r3 >>= 32` clang `(u32)x` idiom), op_u32 ends up
    //     false → 64-bit SHL — which is what cvc5's QF_BV rewriter
    //     recognizes as `(bvlshr (bvshl X N) N)` and folds via a
    //     fast-path rule, sidestepping the SAT bit-blast that otherwise
    //     produces a wide FACTORING step exceeding BCF's u8 clause-width.
    if let (Some(d), Operand::Imm(k)) = (dst.bcf_idx(), src) {
        // Snapshot post-op bounds before borrowing state.bcf mutably —
        // the kernel uses these to override op_u32/op_s32 when LSH
        // widens the value out of u32 range.
        let dst_bounds_post = bcf_reg_bounds(state, dst);
        if let Some(bcf) = state.bcf.as_mut() {
            // Kernel-mirror bcf_alu early bail-out (verifier.c:15220-15223).
            if bcf.clear_reg_if_const(d, &dst_bounds_post) {
                return;
            }
            let shift_amount = if width == Width::W32 {
                (*k as u32) & 0x1F
            } else {
                (*k as u32) & 0x3F
            };
            // Kernel `op_u32 = fit_u32(dst_pre) && fit_u32(src); ...
            // op_u32 &= fit_u32(dst_post)` — the source operand is an
            // immediate-from-fake_reg constant, which trivially fits.
            let op_u32 = dst_bounds_pre.fit_u32() && dst_bounds_post.fit_u32();
            let op_s32 = dst_bounds_pre.fit_s32() && dst_bounds_post.fit_s32();
            let alu32_class = width == Width::W32;
            let alu32 = alu32_class || op_u32 || op_s32;
            let bits: u16 = if alu32 { 32 } else { 64 };

            let dst_expr = bcf.reg_expr(d, &dst_bounds_pre, alu32);
            let k_expr = bcf.add_val(shift_amount as u64, alu32);
            let alu_result = bcf.add_alu(crate::refinement::bcf::BPF_LSH, dst_expr, k_expr, bits);

            let final_idx = if alu32 || op_u32 {
                bcf.add_extend(false, 32, 64, alu_result)
            } else if op_s32 {
                bcf.add_extend(true, 32, 64, alu_result)
            } else {
                alu_result
            };
            bcf.bind_reg(d, final_idx);
        }
    } else if let (Some(d), Operand::Reg(sr)) = (dst.bcf_idx(), src) {
        // Reg-source SHL. Kernel-faithful (evidence: kernel route-A
        // 513B has ZERO LSH nodes despite `pc45 r1<<=r7` with r7
        // *variable*; kernel route-C 706B has exactly one LSH for
        // `pc68 w2<<=w9` with w9 *const 3*). So mirror the kernel
        // ONLY when the shift-amount reg is a known constant — then
        // it is semantically an immediate shift, build
        // `LSH(reg_expr(dst), VAL(c))` exactly like the Imm path
        // (this is what produced kernel route-C's `LSH(v4,3)`). A
        // variable shift amount clears the expr (the prior behavior,
        // which kept routes A/B converged — the kernel emits no LSH
        // there either).
        let src_const = state.get_tnum(*sr).const_value();
        if let Some(c) = src_const {
            let shift_amount = if width == Width::W32 {
                (c as u32) & 0x1F
            } else {
                (c as u32) & 0x3F
            };
            let dst_bounds_post = bcf_reg_bounds(state, dst);
            if let Some(bcf) = state.bcf.as_mut() {
                // Kernel-mirror bcf_alu early bail-out (verifier.c:15220-15223).
                if bcf.clear_reg_if_const(d, &dst_bounds_post) {
                    return;
                }
                let op_u32 = dst_bounds_pre.fit_u32() && dst_bounds_post.fit_u32();
                let op_s32 = dst_bounds_pre.fit_s32() && dst_bounds_post.fit_s32();
                let alu32_class = width == Width::W32;
                let alu32 = alu32_class || op_u32 || op_s32;
                let bits: u16 = if alu32 { 32 } else { 64 };

                let dst_expr = bcf.reg_expr(d, &dst_bounds_pre, alu32);
                let k_expr = bcf.add_val(shift_amount as u64, alu32);
                let alu_result =
                    bcf.add_alu(crate::refinement::bcf::BPF_LSH, dst_expr, k_expr, bits);
                let final_idx = if alu32 || op_u32 {
                    bcf.add_extend(false, 32, 64, alu_result)
                } else if op_s32 {
                    bcf.add_extend(true, 32, 64, alu_result)
                } else {
                    alu_result
                };
                bcf.bind_reg(d, final_idx);
            }
        } else if let Some(bcf) = state.bcf.as_mut() {
            // Variable shift amount — kernel emits no LSH expr here.
            bcf.clear_reg(d);
        }
    } else if let Some(d) = dst.bcf_idx()
        && let Some(bcf) = state.bcf.as_mut()
    {
        bcf.clear_reg(d);
    }
}

pub(crate) fn handle_arsh(state: &mut State, width: Width, dst: Reg, src: &Operand) {
    if mark_unknown_if_oversized_shift(state, width, dst, src) {
        return;
    }
    // Pre-op BCF bounds snapshot — same convention as handle_shr above.
    // BCF emission at bottom of the Imm-src branch chains the kernel-shape
    // `ARSH_32(reg_expr32, shift_amount)` + ZEXT to 64 onto dst's cache.
    // Without this hook, programs like `unreachable_arsh.bpf.o` produce
    // path_conds with a freshly-materialized VAR for dst instead of the
    // kernel's ARSH chain, and the canonical hash diverges.
    let dst_bounds_pre_bcf = bcf_reg_bounds(state, dst);

    match src {
        Operand::Imm(k) => {
            let k = *k as u32;
            let shift_amount = if width == Width::W32 {
                k & 0x1F
            } else {
                k & 0x3F
            };

            let old_tnum = state.get_tnum(dst);
            let (old_lo, old_hi) = state.domain.get_interval(dst);
            let (old_s32_min, old_s32_max) = state.domain.get_s32_bounds(dst);
            state.domain.forget(dst);

            if width == Width::W32 {
                let truncated_tnum = old_tnum.trunc32();

                // Update s32 bounds explicitly via shift rules
                let mut new_s32_min = i32::MIN;
                let mut new_s32_max = i32::MAX;

                let min_possible = i32::MIN >> shift_amount;
                let max_possible = i32::MAX >> shift_amount;

                if old_s32_min != i32::MIN && old_s32_max != i32::MAX {
                    new_s32_min = old_s32_min >> shift_amount;
                    new_s32_max = old_s32_max >> shift_amount;
                } else {
                    let trunc_lo = truncated_tnum.min_value() as u32;
                    let trunc_hi = truncated_tnum.max_value() as u32;

                    let signed_lo = trunc_lo as i32;
                    let signed_hi = trunc_hi as i32;
                    if signed_lo <= signed_hi && (signed_lo < 0) == (signed_hi < 0) {
                        new_s32_min = signed_lo >> shift_amount;
                        new_s32_max = signed_hi >> shift_amount;
                    }
                }

                // Absolute structural limit of ARSH
                new_s32_min = new_s32_min.max(min_possible);
                new_s32_max = new_s32_max.min(max_possible);

                state.domain.set_s32_bounds(dst, new_s32_min, new_s32_max);

                if new_s32_min >= 0 {
                    state.domain.assume_ge_imm(dst, new_s32_min as i64);
                    state.domain.assume_le_imm(dst, new_s32_max as i64);
                } else {
                    state.domain.assume_ge_imm(dst, 0);
                    state.domain.assume_le_imm(dst, u32::MAX as i64);
                }

                let sign_bit = (truncated_tnum.value >> 31) & 1;
                let sign_unknown = (truncated_tnum.mask >> 31) & 1;

                let mut sext_tnum = truncated_tnum;
                let upper_mask = 0xFFFFFFFF00000000;

                if sign_unknown != 0 {
                    sext_tnum.mask |= upper_mask;
                    sext_tnum.value &= !upper_mask;
                } else if sign_bit != 0 {
                    sext_tnum.value |= upper_mask;
                }

                let arsh_result = sext_tnum.arsh_imm(shift_amount as u64);
                let new_tnum = arsh_result.trunc32();
                state.set_tnum(dst, new_tnum);
            } else {
                if shift_amount == 32 {
                    let lower_32_bits = 0xFFFFFFFF_u64;
                    let lower_known_zero = (old_tnum.mask & lower_32_bits) == 0
                        && (old_tnum.value & lower_32_bits) == 0;
                    if lower_known_zero {
                        let new_lo = if old_lo != i64::MIN {
                            (old_lo >> 32).max(i32::MIN as i64)
                        } else {
                            i32::MIN as i64
                        };
                        let new_hi = if old_hi != i64::MAX {
                            (old_hi >> 32).min(i32::MAX as i64)
                        } else {
                            i32::MAX as i64
                        };

                        state.domain.assume_ge_imm(dst, new_lo);
                        state.domain.assume_le_imm(dst, new_hi);

                        let new_tnum = old_tnum.arsh_imm(shift_amount as u64);
                        state.set_tnum(dst, new_tnum);
                        sync_tnum_to_bounds(state, dst);
                        return;
                    }
                }

                // ARSH by K structurally bounds the result to
                // [i64::MIN >> K, i64::MAX >> K] for ANY input — the top K+1
                // bits become the sign extension. The W32 path already
                // applies this "absolute structural limit"; the W64 path
                // previously set interval bounds ONLY when the input was
                // already finite, leaving the result unbounded otherwise.
                // That broke the shl-K/arsh-K sign-extend idiom (USDT
                // `(s16)x`: `r1 <<= 48; r1 s>>= 48`): the preceding shl
                // widens [0,65535] past the signed boundary and resets it to
                // full, so arsh saw an unbounded input and produced an
                // unbounded result → a later `ptr += r1` hit the "unbounded
                // min value" ptr-arith reject (test_usdt / test_urandom_usdt).
                // arsh is monotonic for signed values, so intersect the
                // structural bound with the per-side shifted input bound.
                if shift_amount > 0 {
                    let mut new_lo = i64::MIN >> shift_amount;
                    let mut new_hi = i64::MAX >> shift_amount;
                    if old_lo != i64::MIN {
                        new_lo = new_lo.max(old_lo >> shift_amount);
                    }
                    if old_hi != i64::MAX {
                        new_hi = new_hi.min(old_hi >> shift_amount);
                    }
                    state.domain.assume_ge_imm(dst, new_lo);
                    state.domain.assume_le_imm(dst, new_hi);
                } else if old_lo != i64::MIN && old_hi != i64::MAX {
                    state.domain.assume_ge_imm(dst, old_lo);
                    state.domain.assume_le_imm(dst, old_hi);
                }

                let new_tnum = old_tnum.arsh_imm(shift_amount as u64);
                state.set_tnum(dst, new_tnum);
            }

            sync_tnum_to_bounds(state, dst);
        }
        Operand::Reg(_) => {
            state.domain.forget(dst);

            if width == Width::W32 {
                state.domain.assume_ge_imm(dst, i32::MIN as i64);
                state.domain.assume_le_imm(dst, i32::MAX as i64);
            }

            state.set_tnum(dst, Tnum::unknown());
            sync_tnum_to_bounds(state, dst);
        }
    }

    // --- BCF symbolic mirror for ARSH-imm. Mirrors kernel `bcf_alu`
    //     (verifier.c:15139) with the kernel-shape width discipline:
    //     for W32 ARSH (or W64 ARSH where dst fits in u32/s32), emits
    //     `ARSH_32(reg_expr32, shift_amount)` and wraps the result with
    //     ZEXT (or SEXT for s32) to 64 for the cached form. Reg-source
    //     ARSH stays conservative (clear) for now. ---
    if let (Some(d), Operand::Imm(k)) = (dst.bcf_idx(), src) {
        let dst_bounds_post = bcf_reg_bounds(state, dst);
        if let Some(bcf) = state.bcf.as_mut() {
            // Kernel-mirror bcf_alu early bail-out (verifier.c:15220-15223).
            if bcf.clear_reg_if_const(d, &dst_bounds_post) {
                return;
            }
            let shift_amount = if width == Width::W32 {
                (*k as u32) & 0x1F
            } else {
                (*k as u32) & 0x3F
            };
            let op_u32 = dst_bounds_pre_bcf.fit_u32();
            let op_s32 = dst_bounds_pre_bcf.fit_s32();
            let alu32_class = width == Width::W32;
            let alu32 = alu32_class || op_u32 || op_s32;
            let bits: u16 = if alu32 { 32 } else { 64 };

            let dst_expr = bcf.reg_expr(d, &dst_bounds_pre_bcf, alu32);
            let k_expr = bcf.add_val(shift_amount as u64, alu32);
            let alu_result = bcf.add_alu(crate::refinement::bcf::BPF_ARSH, dst_expr, k_expr, bits);

            let final_idx = if alu32 || op_u32 {
                bcf.add_extend(false, 32, 64, alu_result)
            } else if op_s32 {
                bcf.add_extend(true, 32, 64, alu_result)
            } else {
                alu_result
            };
            bcf.bind_reg(d, final_idx);
        }
    } else if let (Some(d), Operand::Reg(sr)) = (dst.bcf_idx(), src) {
        // Const-valued register ARSH == immediate ARSH (kernel
        // is_safe_to_compute_dst_reg_range shift clause). Mirrors
        // handle_shl/handle_shr's const-reg gate.
        let src_const = state.get_tnum(*sr).const_value();
        if let Some(c) = src_const {
            let shift_amount = if width == Width::W32 {
                (c as u32) & 0x1F
            } else {
                (c as u32) & 0x3F
            };
            let dst_bounds_post = bcf_reg_bounds(state, dst);
            if let Some(bcf) = state.bcf.as_mut() {
                // Kernel-mirror bcf_alu early bail-out (verifier.c:15220-15223).
                if bcf.clear_reg_if_const(d, &dst_bounds_post) {
                    return;
                }
                let op_u32 = dst_bounds_pre_bcf.fit_u32();
                let op_s32 = dst_bounds_pre_bcf.fit_s32();
                let alu32_class = width == Width::W32;
                let alu32 = alu32_class || op_u32 || op_s32;
                let bits: u16 = if alu32 { 32 } else { 64 };

                let dst_expr = bcf.reg_expr(d, &dst_bounds_pre_bcf, alu32);
                let k_expr = bcf.add_val(shift_amount as u64, alu32);
                let alu_result =
                    bcf.add_alu(crate::refinement::bcf::BPF_ARSH, dst_expr, k_expr, bits);
                let final_idx = if alu32 || op_u32 {
                    bcf.add_extend(false, 32, 64, alu_result)
                } else if op_s32 {
                    bcf.add_extend(true, 32, 64, alu_result)
                } else {
                    alu_result
                };
                bcf.bind_reg(d, final_idx);
            }
        } else if let Some(bcf) = state.bcf.as_mut() {
            // Variable shift amount — kernel emits no ARSH expr here.
            bcf.clear_reg(d);
        }
    } else if let Some(d) = dst.bcf_idx()
        && let Some(bcf) = state.bcf.as_mut()
    {
        bcf.clear_reg(d);
    }
}

pub(crate) fn handle_rsh(state: &mut State, width: Width, dst: Reg, src: &Operand) {
    // NOTE: BCF symbolic mirror lives on `handle_shr` (the live dispatch
    // target). `AluOp::Rsh` exists in the AST but the parser never emits
    // it, so this handler is dead in practice and a hook here would never
    // fire.
    match src {
        Operand::Imm(k) => {
            let k = *k as u32;
            let shift_amount = if width == Width::W32 {
                k & 0x1F
            } else {
                k & 0x3F
            };

            let (old_lo, old_hi) = state.domain.get_interval(dst);
            state.domain.forget(dst);

            if old_lo != i64::MIN && old_hi != i64::MAX {
                let (lo, hi) = (old_lo, old_hi);
                if lo >= 0 {
                    let new_lo = (lo as u64 >> shift_amount) as i64;
                    let new_hi = (hi as u64 >> shift_amount) as i64;
                    state.domain.assume_ge_imm(dst, new_lo);
                    state.domain.assume_le_imm(dst, new_hi);
                } else {
                    state.domain.assume_ge_imm(dst, 0);
                    if shift_amount > 0 {
                        state
                            .domain
                            .assume_le_imm(dst, (u64::MAX >> shift_amount) as i64);
                    }
                }
            }

            if width == Width::W32 {
                state.domain.apply_and_imm(dst, 0xFFFFFFFF);
            }

            let t = state.get_tnum(dst);
            let new_t = t.rsh_imm(shift_amount as u64);
            state.set_tnum(dst, new_t);
        }
        Operand::Reg(_) => {
            state.domain.forget(dst);
            state.domain.assume_ge_imm(dst, 0);

            if width == Width::W32 {
                state.domain.assume_le_imm(dst, u32::MAX as i64);
                state.set_tnum(dst, Tnum::u32_unknown());
            } else {
                state.set_tnum(dst, Tnum::unknown());
            }
        }
    }

    sync_tnum_to_bounds(state, dst);
}
