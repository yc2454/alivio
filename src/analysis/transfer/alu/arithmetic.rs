// src/analysis/transfer/alu/arithmetic.rs

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::{RegType, TypeState};
use crate::analysis::machine::state::State;
use crate::ast::{Operand, Width};
use crate::domains::tnum::Tnum;
use log::debug;

use super::helpers::{
    bcf_reg_bounds, check_ptr_bounds, emit_bcf_alu_binop, emit_bcf_alu_unary, sync_tnum_to_bounds,
};

pub(crate) fn handle_add(
    env: &mut VerifierEnv,
    state: &mut State,
    in_types: &TypeState,
    width: Width,
    dst: Reg,
    src: &Operand,
) {
    match src {
        Operand::Imm(c) => {
            state.domain.apply_add_imm(dst, *c);
            // Mirror kernel `ptr_reg->off += smin_val` (verifier.c:14391)
            // for the `ptr += K` const-shift case. Only meaningful when
            // dst is currently a pointer; otherwise the entry was already
            // cleared in transfer_alu's catch-all.
            if in_types.get(dst).is_pointer() {
                let prior = state.ptr_const_off.get(&dst).copied().unwrap_or(0);
                state
                    .ptr_const_off
                    .insert(dst, prior.wrapping_add(*c as i64));
            }
        }
        Operand::Reg(r) => {
            let src_is_ptr = in_types.get(*r).is_pointer();
            let dst_is_ptr = in_types.get(dst).is_pointer();

            if dst_is_ptr && !src_is_ptr {
                // Kernel `check_reg_sane_offset` (verifier.c v6.15 L13923+):
                // when forming a new variable-offset pointer via `ptr +=
                // scalar`, the scalar's smin must not be `S64_MIN`. An
                // unbounded-below scalar produces a pointer whose offset
                // could underflow the base's region, so the kernel rejects
                // with "math between %s pointer and register with unbounded
                // min value is not allowed". This is the load-bearing check
                // for iters.c::loop_state_deps2 — the unsafe `*(r10 + r8)`
                // path reaches this site with r8 having been merged across
                // iter-loop iterations into an unbounded scalar, and the
                // kernel rejects here.
                let (s_lo, _s_hi) = state.domain.get_interval(*r);
                if s_lo == i64::MIN {
                    env.fail(
                        crate::analysis::machine::error::VerificationError::InvalidPointerArithmetic {
                            pc: state.pc,
                        },
                    );
                    return;
                }
                // ptr += scalar: preserve relational info if possible.
                //
                // record the scalar contributor in
                // `var_off_contributor` so variable-offset access sites can
                // call `mark_chain_precision_backward` on the scalar
                // (rather than the base pointer). The walker reaches the
                // same lineage either way, but starting from the scalar
                // avoids polluting the frontier with the pointer reg
                // (which can trip MOV-handling along the chain when the
                // base is a fresh LoadMap/MapValue load).
                state.var_off_contributor.insert(dst, *r);

                // Precision sink at the `ptr += scalar` op itself, mirroring
                // kernel `adjust_ptr_min_max_vals` → `mark_chain_precision`
                // on the offset scalar (verifier.c v6.15 ~L15185; the LL2
                // trace shows `mark_precise: last_idx <ptr+=scalar pc>` for
                // exactly this insn). Deferring this to the downstream
                // access site (memory/access.rs) reaches the same lineage
                // but only *after* the access pc is popped — in the
                // forward-worklist that can be later than a sibling path's
                // prune check at an ancestor pc, leaving the scalar
                // imprecise in the cached ancestor so regsafe treats it as
                // a wildcard and a check_ids-distinguishable unsafe path is
                // wrongly subsumed (verifier_scalar_ids.c::
                // check_ids_in_regsafe family). Marking here matches the
                // kernel's sink location and closes that ordering gap.
                if let Some(hidx) = state.history_idx {
                    let pcid = state.parent_cache_id;
                    crate::analysis::flow::precision::mark_chain_precision_backward(env, hidx, pcid, *r);
                }

                let (lo, hi) = state.domain.get_interval(*r);
                // Kernel `ptr_reg->off`: if the scalar is a known
                // constant accumulate it into K (verifier.c:14383-14393);
                // otherwise it's the variable-add case and K is preserved
                // as-is (verifier.c:14414-14415). The catch-all in
                // `transfer_alu` already preserved `ptr_const_off[dst]`
                // for Add-on-pointer, so the variable-add branch needs no
                // explicit update.
                if lo == hi && lo != i64::MIN && lo != i64::MAX {
                    let prior = state.ptr_const_off.get(&dst).copied().unwrap_or(0);
                    state.ptr_const_off.insert(dst, prior.wrapping_add(lo));
                    // Known constant: shift all relations exactly
                    state.domain.apply_add_imm(dst, lo);
                } else {
                    // Non-constant: zone needs forget+assign to set up fresh
                    // constraint-based tracking. Interval mode must skip this
                    // to preserve PtrOffset (var_off updated by apply_add_reg).
                    if !state.domain.is_interval_mode() {
                        if let Some(off) = RegType::get_ptr_offset(&in_types.get(dst)) {
                            state.domain.forget(dst);
                            state.domain.assign_interval(dst, off, off);
                        }
                    }
                    state.domain.apply_add_reg(dst, *r);
                }
            } else if src_is_ptr && !dst_is_ptr {
                // scalar += ptr
                let (lo, hi) = state.domain.get_interval(dst);
                if lo == hi && lo != i64::MIN && lo != i64::MAX {
                    state.domain.assign_reg_offset(dst, *r, lo);
                } else {
                    // For interval mode, combine ptr's PtrOffset with scalar's range
                    state.domain.apply_scalar_add_ptr(dst, *r, lo, hi);

                    // For zone domain, use constraint-based tracking
                    if !state.domain.is_interval_mode() {
                        if let Some(off) = RegType::get_ptr_offset(&in_types.get(*r)) {
                            state.domain.forget(*r);
                            state.domain.assign_interval(*r, off, off);
                        }
                        state.domain.forget(dst);
                        if hi != i64::MAX {
                            state.domain.add_constraint(dst, *r, hi);
                        }
                        if lo != i64::MIN && lo > i64::MIN {
                            state.domain.add_constraint(*r, dst, -lo);
                        }
                        state.domain.close();
                    }
                }
            } else {
                // scalar += scalar, ptr += ptr, etc.
                state.domain.apply_add_reg(dst, *r);
            }
        }
    }

    // Tnum / sync_tnum_to_bounds are scalar-domain bookkeeping. When the dst
    // is (or stays) a pointer and the src is a scalar, the dst's tnum
    // represents the offset within the base, not the absolute address —
    // syncing it to DBM bounds-from-zero installs a bogus absolute bound
    // on the pointer reg, which `check_map_access`'s variable-offset path
    // then reads as a wildly inflated range. Skip it for that case and
    // clear any stale scalar-era tnum the dst carried from before it
    // became a pointer.
    let dst_is_ptr_post = state.types.get(dst).is_pointer();
    let src_is_ptr = match src {
        Operand::Imm(_) => false,
        Operand::Reg(r) => in_types.get(*r).is_pointer(),
    };

    // --- BCF symbolic mirror. Mirrors kernel `bcf_alu` (verifier.c:15139)
    //     with kernel-shape width discipline. For W32 ADD or for W64 ADD
    //     where dst fits in u32 post-op, emits ADD_32(reg32, rhs32) then
    //     ZEXT.
    //
    //     **Pointer+imm is skipped**: kernel doesn't update the pointer
    //     reg's BCF expr for pure const offset bookkeeping — only the
    //     variable contribution flows through `bcf_expr`. This mirrors
    //     kernel behavior at adjust_ptr_min_max_vals (verifier.c:15185).
    //     Without this, zovia would embed the -16 of `r2 += -16` into
    //     the symbolic expression, diverging structurally from kernel. ---
    let dst_bounds_pre = bcf_reg_bounds(state, dst);
    let src_bounds_pre = match src {
        Operand::Reg(r) => Some(bcf_reg_bounds(state, *r)),
        _ => None,
    };
    // Hoisted outside the &mut state.bcf borrow.
    let dst_bounds_post = bcf_reg_bounds(state, dst);
    if let Some(d) = dst.bcf_idx() {
        if let Some(bcf) = state.bcf.as_mut() {
            // **Pointer + immediate is skipped** — kernel handles `ptr += K`
            // by accumulating K into the pointer reg's `off` bookkeeping
            // field (verifier.c:15296-15308), leaving `bcf_expr` alone.
            // refine_stack.rs / refine_map.rs reconstruct the const offset
            // from the abstract-domain distance interval.
            let skip_ptr_imm = dst_is_ptr_post && matches!(src, Operand::Imm(_));
            let skip = src_is_ptr || skip_ptr_imm;
            if skip {
                if !dst_is_ptr_post {
                    bcf.clear_reg(d);
                }
                // Pointer + imm: leave dst.bcf_expr at its current value
                // (the variable contributor only).
            } else if !dst_is_ptr_post && bcf.clear_reg_if_const(d, &dst_bounds_post) {
                // Kernel-mirror bcf_alu early bail-out (verifier.c:15220-15223):
                // skip materialization when the scalar result is a known const.
                // Gated on !dst_is_ptr_post so pointer-arith chains (whose
                // bcf_expr tracks the variable contributor independently)
                // are unaffected.
            } else {
                let op_u32 = dst_bounds_post.fit_u32();
                let op_s32 = dst_bounds_post.fit_s32();
                let alu32_class = width == Width::W32;
                // **Pointer ALU forces 64-bit BCF ops.** Kernel calls
                // `__mark_reg32_unbounded(dst_reg)` for ptr arithmetic
                // (verifier.c:15282), which makes fit_u32/fit_s32 false
                // and forces `bcf_alu` into its 64-bit arm. We mirror
                // that by short-circuiting `alu32` here.
                let alu32 = if dst_is_ptr_post {
                    false
                } else {
                    alu32_class || op_u32 || op_s32
                };
                let bits: u16 = if alu32 { 32 } else { 64 };

                let dst_expr = bcf.reg_expr(d, &dst_bounds_pre, alu32);
                let rhs_expr = match src {
                    Operand::Imm(c) => {
                        let v = if width == Width::W32 {
                            (*c as u32) as u64
                        } else {
                            *c as u64
                        };
                        bcf.add_val(v, alu32)
                    }
                    Operand::Reg(r) => match r.bcf_idx() {
                        Some(si) => bcf.reg_expr(si, &src_bounds_pre.unwrap(), alu32),
                        None => bcf.add_val(0, alu32),
                    },
                };
                let alu_result =
                    bcf.add_alu(crate::refinement::bcf::BPF_ADD, dst_expr, rhs_expr, bits);
                // Force-64 path (ptr arithmetic) skips extension entirely.
                let final_idx = if dst_is_ptr_post {
                    alu_result
                } else if alu32 || op_u32 {
                    bcf.add_extend(false, 32, 64, alu_result)
                } else if op_s32 {
                    bcf.add_extend(true, 32, 64, alu_result)
                } else {
                    alu_result
                };
                bcf.bind_reg(d, final_idx);
            }
        }
    }

    if dst_is_ptr_post && !src_is_ptr {
        state.set_tnum(dst, Tnum::unknown());
        if width == Width::W32 {
            state.domain.apply_w32_truncation(dst);
        }
        check_ptr_bounds(state, dst);
    } else {
        let dst_tnum = state.get_tnum(dst);
        let new_tnum = match src {
            Operand::Imm(c) => dst_tnum.add_imm(*c),
            Operand::Reg(r) => dst_tnum.add(state.get_tnum(*r)),
        };
        let new_tnum = if width == Width::W32 {
            new_tnum.trunc32()
        } else {
            new_tnum
        };
        state.set_tnum(dst, new_tnum);

        // Kernel W32 pipeline: `scalar32_min_max_add` computes the s32/u32
        // halves (kept unless that 32-bit pair itself overflows) and
        // `zext_32_to_64` then ASSIGNS the 64-bit bounds from them
        // (transfer_alu step 6b / __reg_assign_32_into_64). The interval
        // domain's apply_add_imm/reg mirrors the 32-bit halves, so the
        // legacy 64-bit-interval truncation here is redundant — and its
        // not-tight arm does forget(dst), WIPING the just-computed s32
        // (e.g. `w1 += -1` on [0,255]: the kernel keeps s32=[-1,254];
        // a wiped state would re-derive s32 full-range and lose the
        // bcf_bound_reg32 preds). Zone mode has no 32-bit-aware ALU ops
        // and still needs the truncation for W32 64-bit correctness.
        if width == Width::W32 && !state.domain.is_interval_mode() {
            state.domain.apply_w32_truncation(dst);
        }

        check_ptr_bounds(state, dst);
        // Kernel order (adjust_scalar_min_max_vals): 32-bit halves →
        // zext_32_to_64 → reg_bounds_sync applies var_off. For a W32 op
        // the truncated-32 tnum's UNSIGNED min/max must not be intersected
        // with the PRE-zext 64-bit SIGNED interval: [0,255]+(-1) has
        // s64=[-1,254] pre-zext, and imposing tnum_min=0 there would
        // cascade (via sync) into s32=[0,254]/u32=[0,0xfe] where the
        // kernel keeps s32=[-1,254] with u32 unbounded.
        // transfer_alu runs the sync AFTER its zext step for W32 interval
        // mode; W64 (and zone) keep the in-handler sync.
        if width == Width::W64 || !state.domain.is_interval_mode() {
            sync_tnum_to_bounds(state, dst);
        }
    }
}

pub(crate) fn handle_sub(
    _env: &mut VerifierEnv,
    state: &mut State,
    in_types: &TypeState,
    width: Width,
    dst: Reg,
    src: &Operand,
) {
    match src {
        Operand::Imm(c) => {
            state.domain.apply_add_imm(dst, -c);
            // Mirror kernel `ptr_reg->off -= smin_val` (verifier.c:14448)
            // for the `ptr -= K` const-shift case.
            if in_types.get(dst).is_pointer() {
                let prior = state.ptr_const_off.get(&dst).copied().unwrap_or(0);
                state
                    .ptr_const_off
                    .insert(dst, prior.wrapping_sub(*c as i64));
            }
        }
        Operand::Reg(r) => {
            let dst_type = in_types.get(dst);
            let src_type = in_types.get(*r);
            let dst_is_ptr = dst_type.is_pointer();
            let src_is_ptr = src_type.is_pointer();

            if dst_is_ptr && !src_is_ptr {
                // ptr -= scalar: try to preserve relational info
                let const_value = state.domain.get_fixed_value(*r);

                if const_value.is_some() {
                    // Scalar is a known constant: exact relational shift
                    let c = const_value.unwrap();
                    state.domain.apply_add_imm(dst, -c);
                    // Mirror `ptr_reg->off -= smin_val` for const-reg case
                    // (verifier.c:14439-14450). Variable-scalar case: K is
                    // preserved by the transfer_alu catch-all and we add
                    // nothing here.
                    let prior = state.ptr_const_off.get(&dst).copied().unwrap_or(0);
                    state.ptr_const_off.insert(dst, prior.wrapping_sub(c));
                } else {
                    // Bounded but not constant: fall back to interval
                    state.domain.apply_sub_reg(dst, *r);
                }
            } else if is_same_family_ptr_subtraction(&dst_type, &src_type) {
                // ptrX - ptrX (same packet family): result is the scalar
                // byte distance between the two pointers within the same
                // packet region. apply_sub_reg already carries the DBM
                // relation `dst = old_dst - src` so any constraint the
                // verifier proved on `old_dst - src` (e.g. == 20) is
                // preserved as the new dst's bounds. Type demotion to
                // ScalarValue happens in `update_ptr_arithmetic_type` via
                // `handle_scalar_arithmetic_type` once we drop into that
                // path; we just compute the domain effect here.
                state.domain.apply_sub_reg(dst, *r);
            } else if is_packet_ptr_subtraction(&dst_type, &src_type) {
                // SPECIAL CASE: Packet Pointer Subtraction (Correlated Branch Support)
                // When computing `dst = packet_end - packet`, the result is a scalar
                // representing the packet length (i.e., @data_end - @data).
                // Standard DBM subtraction computes interval bounds but loses
                // the relationship between the scalar result and the anchor difference.
                // We link the scalar result to @data_end by copying the src
                // register's anchor constraints so DBM closure propagates correctly.
                handle_packet_ptr_subtraction(state, dst, *r);
            } else {
                // scalar -= scalar, scalar -= ptr, other ptr -= ptr
                state.domain.apply_sub_reg(dst, *r);
            }
        }
    }

    // See handle_add for rationale: when dst is a pointer and src is a
    // scalar, skip the absolute-address tnum propagation and reset the
    // tnum to unknown so a stale scalar-era value can't leak into DBM
    // via sync_tnum_to_bounds.
    let dst_is_ptr_post = state.types.get(dst).is_pointer();
    let src_is_ptr = match src {
        Operand::Imm(_) => false,
        Operand::Reg(r) => in_types.get(*r).is_pointer(),
    };

    // --- BCF symbolic mirror. Mirrors kernel `bcf_alu` (verifier.c:15139)
    //     with kernel-shape width discipline, analogous to `handle_add`.
    //     For W32 SUB or for W64 SUB where dst fits in u32/s32 post-op,
    //     emits SUB_32(reg32, rhs32) then ZEXT/SEXT back to 64.
    //
    //     **Pointer−immediate is skipped** (same rationale as ptr+imm in
    //     handle_add): kernel handles `ptr -= K` by decrementing the
    //     pointer reg's `off` (verifier.c:14439-14450); `bcf_expr` stays
    //     untouched. The const offset is reconstructed at refine time
    //     from `state.ptr_const_off`. ---
    let dst_bounds_pre = bcf_reg_bounds(state, dst);
    let src_bounds_pre = match src {
        Operand::Reg(r) => Some(bcf_reg_bounds(state, *r)),
        _ => None,
    };
    let dst_bounds_post = bcf_reg_bounds(state, dst);
    if let Some(d) = dst.bcf_idx() {
        if let Some(bcf) = state.bcf.as_mut() {
            let skip_ptr_imm = dst_is_ptr_post && matches!(src, Operand::Imm(_));
            let skip = src_is_ptr || skip_ptr_imm;
            if skip {
                if !dst_is_ptr_post {
                    bcf.clear_reg(d);
                }
                // Pointer − imm: leave dst.bcf_expr at its current value.
            } else if !dst_is_ptr_post && bcf.clear_reg_if_const(d, &dst_bounds_post) {
                // Kernel-mirror bcf_alu early bail-out (verifier.c:15220-15223);
                // see handle_add for full rationale.
            } else {
                let op_u32 = dst_bounds_post.fit_u32();
                let op_s32 = dst_bounds_post.fit_s32();
                let alu32_class = width == Width::W32;
                // Pointer ALU forces 64-bit BCF ops (kernel
                // `__mark_reg32_unbounded` at verifier.c:15282).
                let alu32 = if dst_is_ptr_post {
                    false
                } else {
                    alu32_class || op_u32 || op_s32
                };
                let bits: u16 = if alu32 { 32 } else { 64 };

                let dst_expr = bcf.reg_expr(d, &dst_bounds_pre, alu32);
                let rhs_expr = match src {
                    Operand::Imm(c) => {
                        let v = if width == Width::W32 {
                            (*c as u32) as u64
                        } else {
                            *c as u64
                        };
                        bcf.add_val(v, alu32)
                    }
                    Operand::Reg(r) => match r.bcf_idx() {
                        Some(si) => bcf.reg_expr(si, &src_bounds_pre.unwrap(), alu32),
                        None => bcf.add_val(0, alu32),
                    },
                };
                let alu_result =
                    bcf.add_alu(crate::refinement::bcf::BPF_SUB, dst_expr, rhs_expr, bits);
                let final_idx = if dst_is_ptr_post {
                    alu_result
                } else if alu32 || op_u32 {
                    bcf.add_extend(false, 32, 64, alu_result)
                } else if op_s32 {
                    bcf.add_extend(true, 32, 64, alu_result)
                } else {
                    alu_result
                };
                bcf.bind_reg(d, final_idx);
            }
        }
    }

    if dst_is_ptr_post && !src_is_ptr {
        state.set_tnum(dst, Tnum::unknown());
        if width == Width::W32 {
            state.domain.apply_w32_truncation(dst);
        }
        let dst_is_ptr = in_types.get(dst).is_pointer();
        if !(dst_is_ptr && src_is_ptr) {
            check_ptr_bounds(state, dst);
        }
    } else {
        let dst_tnum = state.get_tnum(dst);
        let new_tnum = match src {
            Operand::Imm(c) => dst_tnum.sub_imm(*c),
            Operand::Reg(r) => dst_tnum.sub(state.get_tnum(*r)),
        };
        let new_tnum = if width == Width::W32 {
            new_tnum.trunc32()
        } else {
            new_tnum
        };
        state.set_tnum(dst, new_tnum);

        // Same kernel W32 pipeline as handle_add (scalar32_min_max_sub +
        // zext_32_to_64): interval mode's apply_sub_* maintain the 32-bit
        // halves; the legacy truncation's forget(dst) wipes them.
        if width == Width::W32 && !state.domain.is_interval_mode() {
            state.domain.apply_w32_truncation(dst);
        }

        let dst_is_ptr = in_types.get(dst).is_pointer();
        if !(dst_is_ptr && src_is_ptr) {
            check_ptr_bounds(state, dst);
        }

        // Same kernel ordering as handle_add: W32 interval-mode tnum sync
        // runs AFTER transfer_alu's zext (pre-zext intersection poisons
        // the signed views).
        if width == Width::W64 || !state.domain.is_interval_mode() {
            sync_tnum_to_bounds(state, dst);
        }
    }
}

pub(crate) fn handle_neg(state: &mut State, width: Width, dst: Reg) {
    // Pre-op BCF snapshot (before the abstract op), mirroring handle_and.
    let dst_bounds_pre = bcf_reg_bounds(state, dst);

    state.domain.apply_neg(dst);

    if width == Width::W32 {
        state.domain.apply_and_imm(dst, 0xFFFFFFFF);
    }

    let t = state.get_tnum(dst);
    let new_t = if width == Width::W32 {
        t.trunc32()
    } else {
        Tnum::unknown()
    };
    state.set_tnum(dst, new_t);

    // BCF: kernel routes BPF_NEG through bcf_alu's unary path (NEG is
    // in is_safe set) — build NEG(reg_expr(dst)). Was a STALE-bcf_expr
    // gap (no build, no clear).
    emit_bcf_alu_unary(
        state,
        crate::refinement::bcf::BPF_NEG,
        width,
        dst,
        &dst_bounds_pre,
    );
}

pub(crate) fn handle_mul(state: &mut State, width: Width, dst: Reg, src: &Operand) {
    // Pre-op BCF snapshots (before forget), mirroring handle_and.
    let dst_bounds_pre = bcf_reg_bounds(state, dst);
    let src_bounds_pre = match src {
        Operand::Reg(r) => Some(bcf_reg_bounds(state, *r)),
        _ => None,
    };

    match src {
        Operand::Imm(c) => {
            state.domain.apply_mul_imm(dst, *c);
        }
        Operand::Reg(_) => {
            state.domain.forget(dst);
        }
    }

    if width == Width::W32 {
        state.domain.apply_w32_truncation(dst);
    }

    state.set_tnum(dst, Tnum::unknown());

    // BCF: kernel routes BPF_MUL through bcf_alu (in is_safe set) —
    // build MUL(reg_expr(dst), reg_expr(src)). Was a STALE-bcf_expr
    // gap (no build, no clear): zovia widens the tnum to unknown but
    // the symbolic expr must still mirror the kernel exactly.
    emit_bcf_alu_binop(
        state,
        crate::refinement::bcf::BPF_MUL,
        width,
        dst,
        src,
        &dst_bounds_pre,
        src_bounds_pre.as_ref(),
    );
}

pub(crate) fn handle_mod(
    state: &mut State,
    width: Width,
    dst: Reg,
    src: &Operand,
    kernel_faithful: bool,
) {
    // The kernel models BPF_MOD with `__mark_reg_unknown` semantics:
    // `is_safe_to_compute_dst_reg_range` (verifier.c v6.15 L16050)
    // excludes MOD, so dst's bounds are cleared completely. In
    // `kernel_faithful` mode we mirror that — drop bounds entirely so
    // later pointer-arith sites see the same "unbounded min" picture
    // as the kernel does and BCF can emit a bound-refine discharge.
    //
    // Outside kernel_faithful mode (e.g. zone domain), keep the
    // tighter `r0 ∈ [0, divisor-1]` refinement: it's sound and
    // produces fewer benign rejects at non-kernel-mode sites.
    match src {
        Operand::Imm(c) => {
            state.domain.forget(dst);
            if !kernel_faithful && *c > 0 {
                state.domain.assume_ge_imm(dst, 0);
                state.domain.assume_le_imm(dst, c - 1);
            }
        }
        Operand::Reg(r) => {
            let (r_lo, r_hi) = state.domain.get_interval(*r);
            state.domain.forget(dst);

            if !kernel_faithful {
                if r_lo > 0 && r_hi != i64::MAX {
                    state.domain.assume_ge_imm(dst, 0);
                    state.domain.assume_le_imm(dst, r_hi - 1);
                } else if r_lo > 0 {
                    state.domain.assume_ge_imm(dst, 0);
                }
            }
        }
    }

    if width == Width::W32 {
        state.domain.apply_w32_truncation(dst);
    }

    state.set_tnum(dst, Tnum::unknown());

    // BCF: mirror kernel `is_safe_to_compute_dst_reg_range`
    // (verifier.c:16050) — BPF_MOD is not in the safe set, so the
    // kernel takes the `__mark_reg_unknown` path which clears
    // `bcf_expr = -1`. Without clearing here, dst keeps a STALE
    // pre-op expr and a later branch builds its path_cond from the
    // wrong value (faithfulness + latent soundness bug).
    if let Some(d) = dst.bcf_idx()
        && let Some(bcf) = state.bcf.as_mut()
    {
        bcf.clear_reg(d);
    }
}

pub(crate) fn handle_div(state: &mut State, width: Width, dst: Reg, src: &Operand) {
    // Preserve tnum precision for div by a known non-zero immediate.
    // Mirrors kernel reasoning: when both dividend and divisor are
    // fully known the result is exact; div by 1 is a no-op. Anything
    // else (unknown divisor, unknown dividend, divisor=0) collapses to
    // unknown — the kernel rejects div-by-zero before this point.
    //
    // Note: The kernel itself ALWAYS marks DIV-result var_off unknown
    // via `is_safe_to_compute_dst_reg_range` (verifier.c v6.15 L15089),
    // independent of operand const-ness. We're more precise here, which
    // is sound for bound-tracking but may cause divergence at gates
    // that rely on `tnum_is_const(off_reg->var_off)` being false. The
    // PtrToFlowKeys gate ([alu/validation.rs:91]) handles this via the
    // `kernel_unknown_tnum_regs` side channel; see also `tnum_imprecise`
    // tracking on State.
    let new_tnum = match src {
        Operand::Imm(imm) => {
            let imm_u = if width == Width::W32 {
                (*imm as u32) as u64
            } else {
                *imm as u64
            };
            let dst_t = if width == Width::W32 {
                state.get_tnum(dst).trunc32()
            } else {
                state.get_tnum(dst)
            };
            if imm_u == 1 {
                Some(dst_t)
            } else if imm_u != 0
                && let Some(c) = dst_t.const_value()
            {
                let q = if width == Width::W32 {
                    ((c as u32) / (imm_u as u32)) as u64
                } else {
                    c / imm_u
                };
                Some(Tnum::constant(q))
            } else {
                None
            }
        }
        Operand::Reg(_) => None,
    };

    match src {
        Operand::Imm(imm) => state.domain.apply_div_imm(dst, *imm),
        Operand::Reg(r_src) => state.domain.apply_div_reg(dst, *r_src),
    }

    if width == Width::W32 {
        state.domain.apply_and_imm(dst, 0xFFFFFFFF);
    }

    state.set_tnum(dst, new_tnum.unwrap_or_else(Tnum::unknown));
    if let Some(c) = state.get_tnum(dst).const_value() {
        state.domain.assume_eq_imm(dst, c as i64);
    }

    // BCF: mirror kernel `is_safe_to_compute_dst_reg_range`
    // (verifier.c:16050) — BPF_DIV is not in the safe set, so the
    // kernel takes the `__mark_reg_unknown` path which clears
    // `bcf_expr = -1`. zovia may keep a more precise tnum (sound for
    // bounds) but the symbolic expr MUST match the kernel: clear it
    // so a later branch materializes a fresh VAR exactly as the
    // kernel does. Stale expr = faithfulness + latent soundness bug.
    if let Some(d) = dst.bcf_idx()
        && let Some(bcf) = state.bcf.as_mut()
    {
        bcf.clear_reg(d);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Packet Pointer Subtraction Helpers
// ══════════════════════════════════════════════════════════════════════════════

/// Checks if this is a packet pointer subtraction that produces a packet length scalar.
///
/// Valid patterns:
///   - PtrToPacketEnd - PtrToPacket      → packet length (@data_end - @data)
///   - PtrToPacket - PtrToPacketMeta     → metadata length (@data - @data_meta)
///   - PtrToPacketEnd - PtrToPacketMeta  → total length (@data_end - @data_meta)
fn is_packet_ptr_subtraction(dst_type: &RegType, src_type: &RegType) -> bool {
    matches!(
        (dst_type, src_type),
        (RegType::PtrToPacketEnd, RegType::PtrToPacket)
            | (RegType::PtrToPacketEnd, RegType::PtrToPacketMeta)
            | (RegType::PtrToPacket, RegType::PtrToPacketMeta)
    )
}

/// Same-family packet pointer subtraction: both operands share the same
/// packet anchor (e.g. two PtrToPacket regs derived from `data + N`
/// after independent bounds checks). Result is a scalar byte distance,
/// no anchor linkage needed — the DBM relation `dst - src` post
/// `apply_sub_reg` already captures the proven distance.
fn is_same_family_ptr_subtraction(dst_type: &RegType, src_type: &RegType) -> bool {
    matches!(
        (dst_type, src_type),
        (RegType::PtrToPacket, RegType::PtrToPacket)
            | (RegType::PtrToPacketEnd, RegType::PtrToPacketEnd)
            | (RegType::PtrToPacketMeta, RegType::PtrToPacketMeta)
    )
}

/// Handles the special case of packet pointer subtraction.
///
/// When computing `dst = packet_end - packet`, we link the scalar result
/// to the anchor system so that future constraints on dst propagate to anchor
/// relationships via DBM closure.
fn handle_packet_ptr_subtraction(state: &mut State, dst: Reg, src: Reg) {
    // First, perform standard subtraction to compute interval bounds
    state.domain.apply_sub_reg(dst, src);

    let start_anchor = Reg::AnchorData;
    let end_anchor = Reg::AnchorDataEnd;

    // Link dst to @data_end (dst <= @data_end)
    // Copy from src since src is at @data, and @data <= @data_end
    let dst_to_end = state.domain.get(src, end_anchor);
    state.domain.add_constraint(dst, end_anchor, dst_to_end);

    // Link dst to @data_end in reverse (@data_end - dst relationship)
    let end_to_dst = state.domain.get(end_anchor, src);
    state.domain.add_constraint(end_anchor, dst, end_to_dst);

    // Link @data to Zero so that absolute constraints on dst
    // (like `dst >= 14`) propagate through to anchor relationships.
    //
    // The closure path is: @data → Zero → dst → @data_end
    //   D[@data, dst] = D[@data, Zero] + D[Zero, dst]
    //   D[@data, @data_end] = D[@data, dst] + D[dst, @data_end]
    //
    // By linking @data to Zero (both directions at 0), we ensure:
    //   - D[@data, Zero] = 0 and D[Zero, @data] = 0
    //   - When D[Zero, dst] = -14, then D[@data, dst] = -14
    //   - Then D[@data, @data_end] = -14 + 0 = -14
    state.domain.add_constraint(start_anchor, Reg::Zero, 0);
    state.domain.add_constraint(Reg::Zero, start_anchor, 0);

    state.domain.close();

    debug!(
        "Packet ptr subtraction: linked {} to anchors (D[dst,end]={}, D[end,dst]={})",
        dst.name(),
        dst_to_end,
        end_to_dst
    );
}
