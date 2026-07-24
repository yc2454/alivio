// src/analysis/transfer/alu/bitwise.rs

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::ast::{Operand, Width};
use crate::domains::tnum::Tnum;
use crate::refinement::bcf::{BPF_AND, BPF_OR, BPF_XOR};

use super::helpers::{bcf_reg_bounds, emit_bcf_alu_binop, sync_tnum_to_bounds};

// BCF symbolic mirror for `mov32 dst, src` (W32 Reg→Reg). Mirrors kernel
// `bcf_alu` (verifier.c:15139)'s mov32 shape: reads src in 32-bit form,
// wraps with ZEXT to 64 for the cached form. Without this hook,
// downstream ALU ops (handle_arsh, handle_and, ...) materialize a fresh
// VAR for dst from its current abstract bounds instead of chaining
// through the kernel's `ZEXT(EXTRACT_LO_32(...))` shape, and the
// canonical hash of any later path_cond involving dst diverges from
// the kernel's runtime hash.
fn emit_bcf_mov_w32_reg(state: &mut State, dst: Reg, src: Reg) {
    let (Some(d), Some(s)) = (dst.bcf_idx(), src.bcf_idx()) else { return };
    let src_bounds = bcf_reg_bounds(state, src);
    if let Some(bcf) = state.bcf.as_mut() {
        let src_expr32 = bcf.reg_expr(s, &src_bounds, true);
        let final_idx = bcf.add_extend(false, 32, 64, src_expr32);
        bcf.bind_reg(d, final_idx);
    }
}

pub(crate) fn handle_mov(state: &mut State, width: Width, dst: Reg, src: &Operand) {
    match src {
        Operand::Imm(c) => {
            let v = if width == Width::W32 {
                (*c as u32) as u64
            } else {
                *c as u64
            };
            state.set_tnum(dst, Tnum::constant(v));
            // Kernel bcf mov const bail-out (verifier.c:16416-16421 /
            // :15239): a mov whose result is tnum-const CLEARS
            // dst->bcf_expr instead of binding — the const materializes
            // as a bcf_val literal at its next reference. Also wipes any
            // stale dst binding.
            if let Some(d) = dst.bcf_idx()
                && let Some(bcf) = state.bcf.as_mut()
            {
                bcf.clear_reg(d);
            }
        }
        Operand::Reg(r) => {
            let t = if width == Width::W32 {
                state.get_tnum(*r).trunc32()
            } else {
                state.get_tnum(*r)
            };
            if crate::analysis::trace_pc_in_range(state.pc)
                && dst == crate::analysis::machine::reg::Reg::R3
            {
                eprintln!(
                    "[mov-r3] pc={} w={:?} src={:?} src_ty={:?} src_tn={:?} post_tn={:?}",
                    state.pc, width, r, state.types.get(*r),
                    state.get_tnum(*r), t
                );
            }
            state.set_tnum(dst, t);
            // Kernel bcf mov const bail-out (verifier.c:16416-16421): when
            // the post-mov dst is tnum-const the kernel clears
            // `dst_reg->bcf_expr = -1` and does NOT copy the src chain —
            // the next reference materializes `bcf_val(K)` (the fold).
            // Gate on TNUM-const exactly (not zovia's wider interval
            // const — that over-folds where the kernel keeps the chain).
            if state.get_tnum(dst).is_const() {
                if let Some(d) = dst.bcf_idx()
                    && let Some(bcf) = state.bcf.as_mut()
                {
                    bcf.clear_reg(d);
                }
            } else if width == Width::W32 && dst != *r {
                emit_bcf_mov_w32_reg(state, dst, *r);
            } else if width == Width::W64 && dst != *r {
                // W64 mov: dst.cache = src.cache. Pull src's cached 64-bit
                // expr and bind it to dst so the chain stays intact.
                if let (Some(d), Some(s)) = (dst.bcf_idx(), r.bcf_idx()) {
                    let src_bounds = bcf_reg_bounds(state, *r);
                    if let Some(bcf) = state.bcf.as_mut() {
                        let src_expr = bcf.reg_expr(s, &src_bounds, false);
                        bcf.bind_reg(d, src_expr);
                    }
                }
            }
        }
    }

    // Carry the kernel's `ptr_reg->off` (`ptr_const_off`) across a
    // pointer-to-pointer mov. The `transfer_alu` catch-all already
    // cleared `ptr_const_off[dst]` (mov isn't Add/Sub on a pointer);
    // re-insert here when the source is a pointer-typed register so the
    // copy carries the offset. W32 mov truncates to low 32 bits — if
    // the source is a pointer, treat it the same as W64 (the kernel
    // does W64 type-preservation for ptr-mov; W32 ptr-to-scalar
    // demotion happens later in update_alu_types). `mov dst, R10` has
    // no `ptr_const_off` entry for R10; that means K_dst = 0 (fresh
    // anchor at r10), which matches the kernel's initialization.
    if let Operand::Reg(r) = src {
        if state.types.get(*r).is_pointer() && dst != *r {
            match state.ptr_const_off.get(r).copied() {
                Some(k) => {
                    state.ptr_const_off.insert(dst, k);
                }
                None => {
                    // R10 (or other fresh anchor): K starts at 0.
                    state.ptr_const_off.insert(dst, 0);
                }
            }
            // Carry `var_off_contributor` alongside `ptr_const_off`. A
            // ptr→ptr mov copies the variable-offset chain: if the src
            // pointer had a scalar contributor recorded (from an earlier
            // `ptr += scalar`), the dst pointer inherits it. Without this,
            // refine_map's case classification at a later helper-mem
            // access misreads dst as a constant-offset pointer (`ptr_is_var
            // = false`) and falls into case (i), producing a refine_cond
            // that uses the size reg directly instead of building
            // `ADD(off_expr, size_expr)` for case (iii). cvc5's proof for
            // the case-(i) shape on the trace_sys_enter_execve / similar
            // `r6 += (r0 << 32 >> 32); r1 = r6` flow hits a 338-child
            // FACTORING resolution step (the case-(iii) shape produces a
            // narrow proof). transfer_alu's catch-all already removed
            // dst's entry for !Add/Sub-Imm; re-insert here from src.
            if let Some(&contributor) = state.var_off_contributor.get(r) {
                state.var_off_contributor.insert(dst, contributor);
            }
        }
    }

    match src {
        Operand::Reg(r) => {
            if width == Width::W32 {
                // Snapshot u32-range proof + u32 shadow bounds on `*r`
                // before forgetting `dst`, because (a) for self-mov
                // (dst == *r) forget() wipes the very bounds we need;
                // (b) when full bounds are unbounded but the W32 shadow
                // is tight (e.g. after a `if w1 > 10` jmp32 that only
                // narrowed the shadow), zero-extension `w_d = w_s`
                // makes upper 32 bits zero, so dst's full bound = the
                // source's u32 shadow. Without this, `if w1 > 10; w1
                // = w1; r1 *= 24; ptr += r1` rejects: the self-mov
                // would widen to [0, u32::MAX], blowing the Mul bound.
                let preserved = state.domain.proven_u32_range(*r, Reg::Zero);
                let (u32_min, u32_max) = state.domain.get_u32_bounds(*r);
                let (s32_min, s32_max) = state.domain.get_s32_bounds(*r);
                state.domain.forget(dst);
                if preserved {
                    state.domain.assign_reg(dst, *r);
                } else {
                    state.domain.assume_ge_imm(dst, u32_min as i64);
                    state.domain.assume_le_imm(dst, u32_max as i64);
                }
                // Always propagate src's s32 shadow to dst — W32 mov
                // copies the low 32 bits unchanged, so the s32
                // interpretation of dst matches the s32 view of src.
                // Required for LSM int-hook `return ret;` patterns
                // where `ret` was bounded `[-MAX_ERRNO, 0]` in s32 at
                // entry and the W32 mov before exit must preserve
                // that band for the retval rule check.
                state.domain.set_s32_bounds(dst, s32_min, s32_max);
            } else {
                if dst == *r {
                    return;
                }
                // Copy register state including pointer offset info
                state.domain.assign_reg(dst, *r);
            }
        }
        Operand::Imm(c) => {
            let c64 = if width == Width::W32 {
                (*c as u32) as i64
            } else {
                *c
            };
            state.domain.forget(dst);
            state.domain.assume_le_imm(dst, c64);
            state.domain.assume_ge_imm(dst, c64);
            // For W32 mov of an immediate, also set the s32 shadow:
            // the assembler-encoded `c` is already a 32-bit value, and
            // `w0 = -1` lands as imm=0xFFFFFFFF (u32). The s32 view is
            // `c as i32` (= -1). Without this, the s32 shadow stays at
            // the default full s32 range and downstream W32 mov-from-reg
            // / retval checks (LSM int-hook `return -EPERM`) lose the
            // s32 precision the kernel uses for retval_range_s32.
            if width == Width::W32 {
                let c32 = *c as i32;
                state.domain.set_s32_bounds(dst, c32, c32);
            }
        }
    }

    // --- BCF symbolic mirror. Mirrors kernel `bcf_mov32` / `bcf_mov`
    //     (verifier.c:16325-16374) with the kernel-shape DAG layout. ---
    let src_bounds = match src {
        Operand::Reg(r) => Some(bcf_reg_bounds(state, *r)),
        _ => None,
    };
    if let (Some(bcf), Some(d)) = (state.bcf.as_mut(), dst.bcf_idx()) {
        match src {
            Operand::Imm(c) => {
                let v = if width == Width::W32 {
                    (*c as u32) as u64
                } else {
                    *c as u64
                };
                let idx = bcf.add_val64(v);
                bcf.bind_reg(d, idx);
            }
            Operand::Reg(r) => {
                let new_idx = match r.bcf_idx() {
                    Some(si) => {
                        let sb = src_bounds.unwrap();
                        let alu32 = width == Width::W32;
                        // 32-bit form for MOV32, 64-bit form for MOV64.
                        let src_expr = bcf.reg_expr(si, &sb, alu32);
                        if alu32 {
                            // MOV32 zero-extends low 32 bits into 64-bit dst.
                            bcf.add_extend(false, 32, 64, src_expr)
                        } else {
                            src_expr
                        }
                    }
                    None => bcf.add_val64(0),
                };
                bcf.bind_reg(d, new_idx);
            }
        }
    }
}

pub(crate) fn handle_and(state: &mut State, width: Width, dst: Reg, src: &Operand) {
    // Pre-op unsigned maxima: the kernel's AND bounds are
    //   u32_max = min(dst pre-op u32_max, src u32_max)  (scalar32_min_max_and, verifier.c:15747)
    //   umax    = min(dst pre-op umax,    src umax)     (scalar_min_max_and,   verifier.c:15778)
    // Captured before `forget` wipes dst (and before the op mutates it,
    // covering the self-AND dst==src case); deriving the result from the
    // mask alone would drop the pre-op bound.
    let (_, pre_u32_max) = state.domain.get_u32_bounds(dst);
    let (_, pre_umax) = state.domain.get_u64_bounds(dst);
    // Kernel src_reg: for BPF_K a known reg from the SIGN-EXTENDED imm
    // (__mark_reg_known(&off_reg, insn->imm), verifier.c:16355), whose
    // subreg const is (u32)imm; for BPF_X the real src reg.
    let (src_u32_max, src_umax, src_tnum) = match src {
        Operand::Imm(imm) => (*imm as u32, *imm as u64, Tnum::constant(*imm as u64)),
        Operand::Reg(r) => (
            state.domain.get_u32_bounds(*r).1,
            state.domain.get_u64_bounds(*r).1,
            state.get_tnum(*r),
        ),
    };

    // Pre-op snapshot for BCF: capture dst's BCF bounds BEFORE the
    // abstract op modifies them. Mirrors the kernel's call ordering at
    // verifier.c:16178 (bcf_alu reads pre-op `dst_reg->bcf_expr` after the
    // abstract op runs, but the operands' bounds are pre-op via the
    // already-materialized cached values). For the reg-source case also
    // snapshot the src reg's bounds (the abstract op only mutates dst, so
    // src is stable, but we must capture before borrowing `state.bcf`).
    let dst_bounds_pre = bcf_reg_bounds(state, dst);
    let src_bounds_pre = match src {
        Operand::Reg(r) => Some(bcf_reg_bounds(state, *r)),
        _ => None,
    };

    // Post-op tnum FIRST — kernel order: `dst_reg->var_off = tnum_and(...)`
    // (verifier.c:16225) precedes both min/max helpers, which read the
    // POST-op var_off for their tnum-derived minima and const checks.
    // For W32 the kernel's zext_32_to_64 tail (verifier.c:16262) subregs
    // the var_off (upper 32 bits KNOWN ZERO — an alu32 result is
    // zero-extended); AND always reaches that tail (is_safe set), so
    // mirror the subreg here (a no-op for the imm case, whose zext'd
    // mask already zeroes the uppers; real effect on reg-src W32).
    let t = state.get_tnum(dst);
    let full_t = match src {
        Operand::Imm(mask) => {
            let mask = if width == Width::W32 {
                (*mask as u32) as u64
            } else {
                *mask as u64
            };
            t.and_imm(mask)
        }
        Operand::Reg(_) => t.and(src_tnum),
    };
    let new_t = if width == Width::W32 {
        Tnum { value: full_t.value & 0xFFFF_FFFF, mask: full_t.mask & 0xFFFF_FFFF }
    } else {
        full_t
    };

    state.domain.forget(dst);

    // scalar32_min_max_and (verifier.c:15730): u32_min from the post-op
    // subreg tnum, u32_max via the min() above, s32 by casting when the
    // u32 range doesn't cross the sign boundary; both-subreg-known
    // short-circuits to the const (__mark_reg32_known).
    let sub_val = (new_t.value & 0xffff_ffff) as u32;
    let dst_sub_known = new_t.mask & 0xffff_ffff == 0;
    let src_sub_known = src_tnum.mask & 0xffff_ffff == 0;
    if src_sub_known && dst_sub_known {
        state.domain.set_u32_bounds(dst, sub_val, sub_val);
        state.domain.set_s32_bounds(dst, sub_val as i32, sub_val as i32);
    } else {
        let u32_max_new = pre_u32_max.min(src_u32_max);
        state.domain.set_u32_bounds(dst, sub_val, u32_max_new);
        if (sub_val as i32) <= (u32_max_new as i32) {
            state.domain.set_s32_bounds(dst, sub_val as i32, u32_max_new as i32);
        }
        // else: s32 stays unbounded (kernel sets S32_MIN/S32_MAX).
    }

    // scalar_min_max_and (verifier.c:15761), W64 only: for a 32-bit op
    // the kernel's 64-bit AND result is overwritten by zext_32_to_64 at
    // the ALU tail (verifier.c:16262; zovia: alu/mod.rs W32 tail calls
    // zext_32_into_64), so computing it here would intersect-in bounds
    // the kernel discards. The both-known case (__mark_reg_known) is
    // equivalent to the const tail below (the kernel's trailing
    // __update_reg_bounds shrinks umax to the const either way).
    if width == Width::W64 && !(src_tnum.mask == 0 && new_t.mask == 0) {
        let umax_new = pre_umax.min(src_umax);
        state.domain.set_u64_bounds(dst, new_t.value, umax_new);
        if (new_t.value as i64) <= (umax_new as i64) {
            state.domain.assume_range(dst, new_t.value as i64, umax_new as i64);
        }
        // else: s64 stays unbounded (kernel sets S64_MIN/S64_MAX).
    }

    state.set_tnum(dst, new_t);

    // Kernel tail of scalar_min_max_and: `__update_reg_bounds(dst_reg)`
    // ("We may learn something more from the var_off", verifier.c:15792)
    // — the file-standard tnum→interval intersection, same as or/xor.
    sync_tnum_to_bounds(state, dst);

    if let Some(c) = new_t.const_value() {
        state.domain.assume_eq_imm(dst, c as i64);
    }

    // Deliberately NO extra refinement for the `x in [-1,0] & mask`
    // ((ret s>>31) & -errno) idiom: the kernel's scalar32_min_max_and has
    // no such rule — with either operand possibly negative it leaves s32
    // at [S32_MIN, S32_MAX]; only tnum + unsigned bounds refine. Keeping
    // only kernel-derivable bounds is the mirror requirement.

    // --- BCF symbolic mirror. Mirrors kernel `bcf_alu` (verifier.c:15166)
    //     with the kernel-shape width discipline. ---
    //
    // Width selection mirrors `adjust_scalar_min_max_vals`
    // (verifier.c:16123-16124, 16209-16210):
    //
    //     op_u32 = fit_u32(dst_reg) && fit_u32(&src_reg);  // PRE-op dst + src
    //     ... op runs ...
    //     op_u32 &= fit_u32(dst_reg);                       // AND POST-op dst
    //
    // i.e. `op_u32 = fit_u32(dst_pre) && fit_u32(src) && fit_u32(dst_post)`
    // (and likewise op_s32). Checking only `dst_post` would wrongly narrow
    // a W64 op whose operand is a full u64 into the 32-bit EXTRACT+ZEXT
    // form; the kernel keeps it plain 64-bit when the pre-op dst does not
    // fit u32. For an immediate source the kernel builds a const `src_reg`
    // from the width-extended imm; a constant always fits s32/u32 except
    // a W64 imm outside the u32 / s32 range.
    let dst_bounds_post = bcf_reg_bounds(state, dst);
    let (src_fits_u32, src_fits_s32) = match (src, &src_bounds_pre) {
        (_, Some(sb)) => (sb.fit_u32(), sb.fit_s32()),
        (Operand::Imm(m), None) => {
            let v = if width == Width::W32 {
                (*m as u32) as i64
            } else {
                *m
            };
            (
                (0..=u32::MAX as i64).contains(&v),
                (i32::MIN as i64..=i32::MAX as i64).contains(&v),
            )
        }
        (Operand::Reg(_), None) => (false, false),
    };
    let op_u32 = dst_bounds_pre.fit_u32() && src_fits_u32 && dst_bounds_post.fit_u32();
    let op_s32 = dst_bounds_pre.fit_s32() && src_fits_s32 && dst_bounds_post.fit_s32();
    let alu32_class = width == Width::W32;
    let alu32 = alu32_class || op_u32 || op_s32;
    let bits: u16 = if alu32 { 32 } else { 64 };

    if let Some(d) = dst.bcf_idx() {
        // Kernel-mirror `bcf_alu` early bail-out (verifier.c:15220-15223):
        // when the post-op value is a known constant, clear `dst`'s
        // bcf_expr instead of materializing the chain — the next
        // `reg_expr` call emits a pure `bcf_val(K)` literal, matching
        // kernel's fresh-replay `bcf_reg_expr` const path. Without this,
        // a later branch on `dst` emits `ZEXT((VAR AND K))` chains for
        // what the kernel emits as bare `K`.
        if let Some(bcf) = state.bcf.as_mut()
            && bcf.clear_reg_if_const(d, &dst_bounds_post)
        {
            return;
        }
        // Extend the AND result back to the 64-bit cached reg slot. ZEXT
        // for alu32/op_u32 cases; SEXT for op_s32; no-op for true 64-bit.
        let extend_back = |bcf: &mut crate::refinement::symbolic::SymbolicState,
                           alu_result: u32|
         -> u32 {
            if alu32 || op_u32 {
                bcf.add_extend(false, 32, 64, alu_result)
            } else if op_s32 {
                bcf.add_extend(true, 32, 64, alu_result)
            } else {
                alu_result
            }
        };
        match src {
            Operand::Imm(mask) => {
                if let Some(bcf) = state.bcf.as_mut() {
                    let dst_expr = bcf.reg_expr(d, &dst_bounds_pre, alu32);
                    let mask_val = if width == Width::W32 {
                        (*mask as u32) as u64
                    } else {
                        *mask as u64
                    };
                    let mask_expr = bcf.add_val(mask_val, alu32);
                    let alu_result = bcf.add_alu(BPF_AND, dst_expr, mask_expr, bits);
                    let final_idx = extend_back(bcf, alu_result);
                    bcf.bind_reg(d, final_idx);
                }
            }
            Operand::Reg(r) => {
                // Reg-source AND: mirror kernel `bcf_alu` (verifier.c:15139)
                // reg-reg handling — `AND(reg_expr(dst), reg_expr(src))`.
                // The faithful analog of handle_add's reg-reg path. When
                // src is a known constant (e.g. an ld_imm64 mask register),
                // `reg_expr` materializes it via its const_val branch as
                // `VAL_64(c)`, so the result is `AND(dst_expr, VAL_64(c))`
                // — exactly the kernel's `r1 &= r3` (r3=ld_imm64) DAG.
                // Without this the expr is dropped and any later branch on
                // dst materializes a bare fresh var, losing the AND that
                // the kernel keeps.
                let si = r.bcf_idx();
                if let (Some(bcf), Some(si)) = (state.bcf.as_mut(), si) {
                    let dst_expr = bcf.reg_expr(d, &dst_bounds_pre, alu32);
                    let src_expr = bcf.reg_expr(
                        si,
                        src_bounds_pre.as_ref().unwrap(),
                        alu32,
                    );
                    let alu_result = bcf.add_alu(BPF_AND, dst_expr, src_expr, bits);
                    let final_idx = extend_back(bcf, alu_result);
                    bcf.bind_reg(d, final_idx);
                } else if let Some(bcf) = state.bcf.as_mut() {
                    // src reg has no BCF slot (shouldn't happen for R0–R10);
                    // stay conservative and drop the expr.
                    bcf.clear_reg(d);
                }
            }
        }
    }
}

pub(crate) fn handle_or(state: &mut State, width: Width, dst: Reg, src: &Operand) {
    // Pre-op BCF snapshots (before forget), mirroring handle_and.
    let dst_bounds_pre = bcf_reg_bounds(state, dst);
    let src_bounds_pre = match src {
        Operand::Reg(r) => Some(bcf_reg_bounds(state, *r)),
        _ => None,
    };

    // Pre-op unsigned minima: the kernel's OR bounds are
    //   u32_min = max(dst pre-op u32_min, src u32_min)  (scalar32_min_max_or, verifier.c:15809)
    //   umin    = max(dst pre-op umin,    src umin)     (scalar_min_max_or,   verifier.c:15839)
    // (OR only sets bits, so x|y >= x and >= y); the maxima come from the
    // post-op tnum (value|mask). Captured before `forget` wipes dst.
    // Zero-extending loads set size-masked tnums, which makes the tnum
    // tight enough for the kernel's own umax formula — e.g. a (u8<<3)
    // feed carries tnum {0, 0x7f8}.
    let (pre_u32_min, _) = state.domain.get_u32_bounds(dst);
    let (pre_umin, _) = state.domain.get_u64_bounds(dst);
    // Kernel src_reg: BPF_K = known reg from the SIGN-EXTENDED imm
    // (__mark_reg_known(&off_reg, insn->imm), verifier.c:16355).
    let (src_u32_min, src_umin, src_tnum) = match src {
        Operand::Imm(c) => (*c as u32, *c as u64, Tnum::constant(*c as u64)),
        Operand::Reg(r) => (
            state.domain.get_u32_bounds(*r).0,
            state.domain.get_u64_bounds(*r).0,
            state.get_tnum(*r),
        ),
    };

    // Post-op tnum FIRST — kernel order: `var_off = tnum_or(...)`
    // (verifier.c:16230) precedes both min/max helpers. For W32 the
    // kernel's zext_32_to_64 tail (verifier.c:16262) subregs the var_off
    // (upper 32 bits KNOWN ZERO — an alu32 result is zero-extended); OR
    // always reaches that tail (is_safe set), so mirror the subreg here.
    let t = state.get_tnum(dst);
    let full_t = match src {
        Operand::Imm(c) => {
            let c = if width == Width::W32 {
                (*c as u32) as u64
            } else {
                *c as u64
            };
            t.or_imm(c)
        }
        Operand::Reg(_) => t.or(src_tnum),
    };
    let new_t = if width == Width::W32 {
        Tnum { value: full_t.value & 0xFFFF_FFFF, mask: full_t.mask & 0xFFFF_FFFF }
    } else {
        full_t
    };

    state.domain.forget(dst);

    // scalar32_min_max_or (verifier.c:15794): u32_min = max of minima,
    // u32_max = subreg-tnum value|mask, s32 by cast when the u32 range
    // doesn't cross the sign boundary; both-subreg-known short-circuits
    // to the const (__mark_reg32_known).
    let sub_val = (new_t.value & 0xffff_ffff) as u32;
    let sub_mask = (new_t.mask & 0xffff_ffff) as u32;
    let src_sub_known = src_tnum.mask & 0xffff_ffff == 0;
    if src_sub_known && sub_mask == 0 {
        state.domain.set_u32_bounds(dst, sub_val, sub_val);
        state.domain.set_s32_bounds(dst, sub_val as i32, sub_val as i32);
    } else {
        let u32_min_new = pre_u32_min.max(src_u32_min);
        let u32_max_new = sub_val | sub_mask;
        state.domain.set_u32_bounds(dst, u32_min_new, u32_max_new);
        if (u32_min_new as i32) <= (u32_max_new as i32) {
            state.domain.set_s32_bounds(dst, u32_min_new as i32, u32_max_new as i32);
        }
        // else: s32 stays unbounded (kernel sets S32_MIN/S32_MAX).
    }

    // scalar_min_max_or (verifier.c:15824), W64 only: an alu32 op's
    // 64-bit result is overwritten by zext_32_to_64 at the ALU tail
    // (zovia: alu/mod.rs W32 tail zext_32_into_64). The both-known case
    // (__mark_reg_known) is equivalent to the const tail below.
    if width == Width::W64 && !(src_tnum.mask == 0 && new_t.mask == 0) {
        let umin_new = pre_umin.max(src_umin);
        let umax_new = new_t.value | new_t.mask;
        state.domain.set_u64_bounds(dst, umin_new, umax_new);
        if (umin_new as i64) <= (umax_new as i64) {
            state.domain.assume_range(dst, umin_new as i64, umax_new as i64);
        }
        // else: s64 stays unbounded (kernel sets S64_MIN/S64_MAX).
    }

    state.set_tnum(dst, new_t);

    // Kernel tail of scalar_min_max_or: __update_reg_bounds
    // (verifier.c:15853) — the file-standard tnum→interval intersection.
    sync_tnum_to_bounds(state, dst);

    if let Some(c) = new_t.const_value() {
        state.domain.assume_eq_imm(dst, c as i64);
    }

    // BCF: kernel routes BPF_OR through bcf_alu (in is_safe set) —
    // build OR(reg_expr(dst), reg_expr(src)) unless dropped. Was a
    // STALE-bcf_expr gap (no build, no clear).
    emit_bcf_alu_binop(
        state,
        BPF_OR,
        width,
        dst,
        src,
        &dst_bounds_pre,
        src_bounds_pre.as_ref(),
    );
}

pub(crate) fn handle_xor(state: &mut State, width: Width, dst: Reg, src: &Operand) {
    // Pre-op BCF snapshots (before forget), mirroring handle_and.
    let dst_bounds_pre = bcf_reg_bounds(state, dst);
    let src_bounds_pre = match src {
        Operand::Reg(r) => Some(bcf_reg_bounds(state, *r)),
        _ => None,
    };

    // Kernel src tnum: BPF_K = known reg from the SIGN-EXTENDED imm
    // (__mark_reg_known(&off_reg, insn->imm), verifier.c:16355). Needed
    // for the src-known checks of the min/max mirrors below.
    let src_tnum = match src {
        Operand::Imm(c) => Tnum::constant(*c as u64),
        Operand::Reg(r) => state.get_tnum(*r),
    };

    // Post-op tnum FIRST — kernel order: `var_off = tnum_xor(...)`
    // (verifier.c:16235) precedes both min/max helpers. For W32 the
    // kernel's zext_32_to_64 tail (verifier.c:16262) subregs the var_off
    // (upper 32 bits KNOWN ZERO); XOR always reaches that tail (is_safe
    // set), so mirror the subreg here.
    let t = state.get_tnum(dst);
    let full_t = match src {
        Operand::Imm(c) => {
            let c = if width == Width::W32 {
                (*c as u32) as u64
            } else {
                *c as u64
            };
            t.xor_imm(c)
        }
        Operand::Reg(_) => t.xor(src_tnum),
    };
    let new_t = if width == Width::W32 {
        Tnum { value: full_t.value & 0xFFFF_FFFF, mask: full_t.mask & 0xFFFF_FFFF }
    } else {
        full_t
    };

    state.domain.forget(dst);

    // scalar32_min_max_xor (verifier.c:15857): both u32 bounds from the
    // post-op subreg tnum (u32_min = value, u32_max = value|mask), s32 by
    // cast when the u32 range doesn't cross the sign boundary;
    // both-subreg-known short-circuits to the const (__mark_reg32_known,
    // same values here).
    let sub_val = (new_t.value & 0xffff_ffff) as u32;
    let sub_mask = (new_t.mask & 0xffff_ffff) as u32;
    let u32_max_new = sub_val | sub_mask;
    state.domain.set_u32_bounds(dst, sub_val, u32_max_new);
    if (sub_val as i32) <= (u32_max_new as i32) {
        state.domain.set_s32_bounds(dst, sub_val as i32, u32_max_new as i32);
    }
    // else: s32 stays unbounded (kernel sets S32_MIN/S32_MAX).

    // scalar_min_max_xor (verifier.c:15886), W64 only: an alu32 op's
    // 64-bit result is overwritten by zext_32_to_64 at the ALU tail
    // (zovia: alu/mod.rs W32 tail zext_32_into_64). umin = tnum value,
    // umax = value|mask, s64 by the cast rule. The both-known case
    // (__mark_reg_known) is equivalent to the const tail below.
    if width == Width::W64 && !(src_tnum.mask == 0 && new_t.mask == 0) {
        let umin_new = new_t.value;
        let umax_new = new_t.value | new_t.mask;
        state.domain.set_u64_bounds(dst, umin_new, umax_new);
        if (umin_new as i64) <= (umax_new as i64) {
            state.domain.assume_range(dst, umin_new as i64, umax_new as i64);
        }
        // else: s64 stays unbounded (kernel sets S64_MIN/S64_MAX).
    }

    state.set_tnum(dst, new_t);

    // Kernel tail of scalar_min_max_xor: __update_reg_bounds
    // (verifier.c:15910) — the file-standard tnum→interval intersection.
    sync_tnum_to_bounds(state, dst);

    if let Some(c) = new_t.const_value() {
        state.domain.assume_eq_imm(dst, c as i64);
    }

    // BCF: kernel routes BPF_XOR through bcf_alu (in is_safe set).
    // Was a STALE-bcf_expr gap (no build, no clear).
    emit_bcf_alu_binop(
        state,
        BPF_XOR,
        width,
        dst,
        src,
        &dst_bounds_pre,
        src_bounds_pre.as_ref(),
    );
}
