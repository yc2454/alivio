// src/analysis/transfer/mod.rs
//
// Transfer function for BPF instruction abstract interpretation.
// This module dispatches to specialized handlers for each instruction type.

pub(crate) mod alu;
mod branch;
pub(crate) mod call;
mod common;
pub mod field_tables;
mod memory;
pub(crate) mod types;

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::error::VerificationError;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use crate::ast::{CallKind, EndianOp, Instr, Operand, Width};
use log::warn;

/// Main transfer function - dispatches to appropriate handler based on instruction type.
pub fn transfer(env: &mut VerifierEnv, mut state: State, instr: &Instr) -> Vec<State> {
    // During a faithful-discharge replay we re-execute an already-explored
    // suffix; it must not mutate shared analysis state (insn_aux_data,
    // history back-patches, etc.) or the main worklist's exploration
    // shifts.
    if !env.replay_mode && state.pc < env.insn_aux_data.len() {
        env.insn_aux_data[state.pc].seen = true;
    }

    match instr {
        Instr::Alu {
            width,
            op,
            dst,
            src,
        } => alu::transfer_alu(env, state, *width, *op, *dst, *src),

        Instr::Endian {
            dst,
            op,
            size,
            width,
        } => transfer_endian(env, state, *dst, *op, *size, *width),

        Instr::If {
            width,
            left,
            op,
            right,
            target,
        } => branch::transfer_if(env, state, *width, *left, *op, *right, *target),

        Instr::Load {
            size,
            dst,
            base,
            off,
        } => memory::transfer_load(env, state, *size, *dst, *base, *off),

        Instr::LoadSx {
            size,
            dst,
            base,
            off,
        } => memory::transfer_load_sx(env, state, *size, *dst, *base, *off),

        Instr::MovSx {
            width,
            src_bits,
            dst,
            src,
        } => alu::transfer_mov_sx(env, state, *width, *src_bits, *dst, *src),

        Instr::Store {
            size,
            base,
            off,
            src,
        } => memory::transfer_store(env, state, *size, *base, *off, src),

        Instr::LoadAcq {
            size,
            dst,
            base,
            off,
        } => {
            if reject_atomic_on_typed_ptr(env, &state, *base) {
                return vec![];
            }
            memory::transfer_load(env, state, *size, *dst, *base, *off)
        }

        Instr::StoreRel {
            size,
            base,
            off,
            src,
        } => {
            if reject_atomic_on_typed_ptr(env, &state, *base) {
                return vec![];
            }
            memory::transfer_store(env, state, *size, *base, *off, &Operand::Reg(*src))
        }

        Instr::LoadPacket {
            size,
            mode,
            offset_imm,
            src,
        } => memory::transfer_packet_load(env, state, *size, *mode, *offset_imm, *src),

        Instr::LoadMap {
            dst,
            kind,
            map_fd,
            off: _,
        } => memory::transfer_map_load(env, state, *dst, *kind, *map_fd),

        Instr::Atomic {
            op,
            size,
            fetch,
            base,
            off,
            src,
        } => memory::transfer_atomic(env, state, *op, *fetch, *size, *base, *off, *src),

        Instr::Call { kind } => match *kind {
            CallKind::Helper { id } => call::transfer_call(env, state, id),
            CallKind::Kfunc { btf_id, .. } => call::transfer_kfunc(env, state, btf_id),
        },

        Instr::CallRel { target } => call::transfer_call_rel(env, state, *target),

        Instr::Jmp { target } => {
            state.pc = *target;
            vec![state]
        }

        Instr::MayGoto { target } => {
            // `may_goto` (BPF_JCOND, v6.8) models a bounded back-edge.
            // The kernel inlines a per-program counter that decrements on
            // every execution of the may_goto, regardless of which edge
            // is taken; once the counter hits zero the may_goto becomes
            // a no-op (fall through). Mirroring that decrement on BOTH
            // successors is what lets the abstract interpreter actually
            // terminate: each loop iteration shrinks the budget, so
            // pruning at the loop head eventually subsumes future
            // iterations once widening (or empty live-regs) makes the
            // body's effect on tracked state stable.
            //
            // also mirror the kernel's static may_goto
            // machinery (`check_cond_jmp_op` BPF_JCOND arm, verifier.c
            // v6.15 ~L16400-16410): on each visit, find a previous
            // explored state at this same insn_idx, run
            // `widen_imprecise_scalars` to coarsen scalars whose abstract
            // value disagrees, and bump `may_goto_depth` on the queued
            // state. The depth bump powers a separate RANGE_WITHIN prune
            // class at this pc (~L19102) and defuses the EXACT inf-loop
            // trap (~L19118). Without this, loops like
            // `for (i=0; i<N && can_loop; i++) { arr[i]; cond_break; }`
            // never converge: `i` is precision-marked at `arr[i]` and
            // each iteration produces a fresh state, but the loop has
            // both an `If`-style exit (`i < N`) and a may_goto, so our
            // `force_widen_for_may_goto` (gated on `only_may_goto_exit`)
            // never fires.
            let fallthrough_pc = state.pc + 1;
            let cur_pc = state.pc;

            // Snapshot a previous explored state at this insn for the
            // widener (kernel `find_prev_entry`). The worklist driver
            // calls `record_state` before `transfer`, so
            // `explored_states[cur_pc].last()` IS the current state —
            // skip it and take the second-most-recent. Without this
            // skip the widener compares cur against itself and never
            // coarsens anything.
            let prev_snapshot: Option<State> = env
                .explored_states
                .get(&cur_pc)
                .and_then(|prev_states| {
                    let mut iter = prev_states.iter().rev().filter(|s| s.pc == cur_pc);
                    iter.next();
                    iter.next()
                })
                .cloned();

            if state.goto_budget() == 0 {
                let mut state_fall = state;
                state_fall.pc = fallthrough_pc;
                state_fall.may_goto_depth = state_fall.may_goto_depth.saturating_add(1);
                if let Some(prev) = prev_snapshot.as_ref() {
                    call::kfunc::widen_imprecise_scalars_at_iter_next(env, prev, &mut state_fall);
                }
                return vec![state_fall];
            }

            // Kernel-faithful (check_cond_jmp_op BPF_JCOND arm, verifier.c
            // v6.15 ~L16400): ONLY the FALLTHROUGH (queued "continue loop"
            // successor) gets `may_goto_depth++` and is widened against the
            // prev entry; the TARGET edge (`*insn_idx += insn->off`) keeps
            // the SAME depth and is NOT widened. The depth counts loop
            // iterations along the continue path, so a may_goto whose target
            // is itself a back-edge (`l0: may_goto l0`, off<0) revisits the
            // may_goto pc with UNCHANGED depth → may_goto_range_within_prune's
            // depth-differ gate does NOT fire and the EXACT inf-loop trap
            // (same may_goto_depth) correctly rejects. Bumping both edges
            // made the back-edge look like progress → false-accept.
            let mut state_taken = state.clone();
            state_taken.consume_goto_budget();
            state_taken.pc = *target;

            let mut state_fall = state;
            state_fall.consume_goto_budget();
            state_fall.pc = fallthrough_pc;
            state_fall.may_goto_depth = state_fall.may_goto_depth.saturating_add(1);

            if let Some(prev) = prev_snapshot.as_ref() {
                call::kfunc::widen_imprecise_scalars_at_iter_next(env, prev, &mut state_fall);
            }

            vec![state_taken, state_fall]
        }

        Instr::Exit => transfer_exit(env, state),
    }
}

/// Kernel rejects BPF_ATOMIC (including LOAD_ACQ / STORE_REL) against
/// ctx/packet/flow_keys pointer bases. Returns true if the program should
/// be rejected — caller then bails out without running the transfer.
fn reject_atomic_on_typed_ptr(env: &mut VerifierEnv, state: &State, base: Reg) -> bool {
    let base_ty = state.types.get(base);
    let is_flow_keys = matches!(
        &base_ty,
        RegType::PtrToBtfId { type_name, .. } if *type_name == "bpf_flow_keys"
    );
    let rejected = matches!(
        base_ty,
        RegType::PtrToCtx
            | RegType::PtrToPacket
            | RegType::PtrToPacketMeta
            | RegType::PtrToPacketEnd
            // Kernel `check_atomic` rejects BPF_ATOMIC against sock-class
            // pointer bases ("BPF_ATOMIC loads from R<N> sock is not
            // allowed"). Mirrors verifier_load_acquire::
            // load_acquire_from_sock_pointer.
            | RegType::PtrToSocket { .. }
            | RegType::PtrToSocketOrNull { .. }
            | RegType::PtrToSockCommon { .. }
            | RegType::PtrToSockCommonOrNull { .. }
            | RegType::PtrToTcpSock { .. }
            | RegType::PtrToTcpSockOrNull { .. }
    ) || is_flow_keys;
    if rejected {
        env.fail(VerificationError::UnsupportedModernFeature {
            pc: state.pc,
            feature: "BPF_ATOMIC (LOAD_ACQ / STORE_REL) against ctx/packet pointer",
        });
    }
    rejected
}

/// Transfer function for Endian (byte swap) instructions.
fn transfer_endian(
    env: &VerifierEnv,
    mut state: State,
    dst: Reg,
    op: EndianOp,
    size: u32,
    width: Width,
) -> Vec<State> {
    // Snapshot the PRE-be16 source bounds before the apply_and_imm
    // narrowing below. Kernel `check_alu_op` BPF_END does
    // `check_reg_arg(dst, SRC_OP)` FIRST — reading dst as source for
    // bcf — which calls `bcf_reg_expr(dst)` with the reg's pre-be16
    // bounds (typically the previous u16/u32 load's tnum, e.g.
    // mask=0xffff after `w4 = *(u16 *)(...)`). This materializes a
    // `VAR_U32 + bcf_bound_reg32`. We mirror by calling reg_expr with
    // these pre-bounds first.
    let pre_endian_bounds = crate::analysis::transfer::alu::helpers::bcf_reg_bounds(&state, dst);

    // 1. Types: Endian ops destroy pointers -> Scalar
    state.types.set(dst, RegType::ScalarValue);

    // Kernel check_alu_op BPF_END/byte-swap arm (verifier.c:16509):
    // `check_reg_arg(env, insn->dst_reg, DST_OP)` — DST_OP is
    // mark_reg_unknown. The swap result carries NO bounds/tnum: no
    // adjust_scalar call, no width mask, no zext_32_to_64 — even for
    // the LE-host-identity le64. A tighter model (e.g. [0,0xffff] after
    // be16) diverges from the kernel's bcf goal shape: the reg folds to
    // const after a later == narrowing where the kernel keeps it
    // unknown. Zone mode keeps the precise model below.
    if env.kernel_faithful_alu {
        state.domain.forget(dst);
        state.set_tnum(dst, crate::domains::tnum::Tnum::unknown());
        state.clear_scalar_id(dst);
        state.precise_regs.remove(&dst);
    } else {
    match op {
        EndianOp::ToLe => {
            match size {
                64 => { /* Identity for LE host; Keep constraints if Width::W64 */ }
                32 => state.domain.apply_and_imm(dst, 0xFFFF_FFFF),
                16 => state.domain.apply_and_imm(dst, 0xFFFF),
                _ => state.domain.forget(dst),
            }
        }
        EndianOp::ToBe => {
            // Big Endian always swaps on LE host -> Value changes non-linearly
            // We must forget the old value.
            // However, we know the new max value based on the swap size.
            match size {
                16 => state.domain.apply_and_imm(dst, 0xFFFF),
                32 => state.domain.apply_and_imm(dst, 0xFFFF_FFFF),
                // 64-bit BE swap: Result is u64 (if Width::W64) or u32 (if Width::W32)
                64 => state.domain.forget(dst),
                _ => state.domain.forget(dst),
            }
        }
        EndianOp::Bswap => {
            // BPF v4 BSWAP: byte-swap of the low `size` bits, independent of
            // host endianness. Result fits in `size` bits — narrow, but the
            // exact value is non-linear so the prior interval is forgotten.
            match size {
                16 => state.domain.apply_and_imm(dst, 0xFFFF),
                32 => state.domain.apply_and_imm(dst, 0xFFFF_FFFF),
                64 => state.domain.forget(dst),
                _ => state.domain.forget(dst),
            }
        }
    }

    // 3. Handle Implicit 32-bit Zero Extension
    // This provides a tighter bound [0, U32_MAX] even if the operation was "Unknown".
    if width == Width::W32 {
        state.domain.apply_and_imm(dst, 0xFFFF_FFFF);
    }
    } // end !kernel_faithful_alu (zone-mode precise model)

    // BCF symbolic mirror for BPF_END. Kernel `check_alu_op` BPF_END
    // (verifier.c:16396) does `check_reg_arg(dst, SRC_OP)` then
    // `check_reg_arg(dst, DST_OP)`. DST_OP's `mark_reg_unknown` clears
    // bcf_expr, but subsequent register-state refinement (tnum updated
    // for the BSWAP width via `tnum_and(0xffff)` etc.) leaves the reg
    // with a concrete bounded tnum (e.g. `mask=0xffff umin=0 umax=65535`
    // post-be16). Kernel's next `bcf_reg_expr(result)` therefore takes
    // the `fit_u32` path → emits `VAR_U32 + bcf_bound_reg32`. Mirror
    // that here by using the actual reg bounds (via `bcf_reg_bounds`)
    // instead of `RegBounds::unknown()`, so the bound preds
    // (`VAR ULE 0xffff`) appear in zovia's bcf graph too.
    if let Some(d) = dst.bcf_idx()
        && let Some(bcf) = state.bcf.as_mut() {
            // Step 1 (SRC_OP read): materialize dst with PRE-be16 bounds
            // (snapshot before apply_and_imm above). Kernel's
            // `check_reg_arg(dst, SRC_OP)` reads dst as a source for
            // bcf — emits `VAR_U32 + bound preds` if the prior tnum
            // fit u32. Without this, zovia misses the bound-pred
            // conjuncts the kernel emits at the SRC read.
            let _src_expr = bcf.reg_expr(d, &pre_endian_bounds, false);

            // Step 2 (DST_OP write): kernel `mark_reg_unknown` clears
            // `bcf_expr = -1`, so next bcf_reg_expr re-materializes
            // fresh. Mirror by clearing the cache and re-emitting an
            // unbounded VAR_64 (matches kernel-shape: byte-swap result
            // is not abstractly bounded post-`mark_reg_unknown`,
            // independent of zovia's tighter domain bound from
            // apply_and_imm above which is preserved for AI precision).
            bcf.clear_reg(d);
            let _ = bcf.reg_expr(
                d,
                &crate::refinement::symbolic::RegBounds::unknown(),
                false,
            );
        }

    state.pc += 1;
    vec![state]
}

/// Transfer function for Exit instruction.
fn transfer_exit(env: &mut VerifierEnv, mut state: State) -> Vec<State> {
    let pc = state.pc;

    let (r0_min, r0_max) = state.domain.get_interval(Reg::R0);

    // Exception-callback exit: when the active analysis pass is
    // verifying an `__exception_cb` body (`analyze_exception_cb`),
    // mirror the kernel's `in_exception_callback_fn` behavior — apply
    // the main-program exit rule at the cb's exit. For fentry/fexit
    // attach flavors, that rule is R0 ∈ [0, 0] (kernel:
    // "At program exit the register R0 has ... should be ..."). We do
    // not enforce this on ordinary fentry main-program exits because
    // the existing corpus relies on the looser local behavior; the
    // tighter rule fires only inside the cb pass.
    if env.analyzing_exception_cb
        && state.at_main_frame()
        && matches!(env.ctx.attach_flavor.as_deref(), Some("fentry") | Some("fexit"))
        && (r0_min != 0 || r0_max != 0) {
            env.fail(VerificationError::InvalidReturnCode { pc: state.pc });
            return vec![];
        }

    // Kernel-aligned: main-program exit return-value precision sink
    // (verifier.c v6.15 `check_return_code` calls
    // `mark_chain_precision(R0)` at the `enforce_retval:` label).
    // CRUCIAL: the kernel only REACHES that label for prog types that
    // enforce a retval range. Types whose `check_return_code` returns 0
    // early — SOCKET_FILTER, unprivileged RAW_TRACEPOINT, non-syscall
    // KPROBE, plain TRACEPOINT/PERF_EVENT, XDP, SCHED_CLS, the `default:`
    // arm, ... — NEVER `mark_chain_precision(R0)`. Firing this sink for
    // every `at_main_frame()` exit (old behavior) over-marked R0 and its
    // entire backward data-dep chain precise (e.g. loop4's accumulator
    // `ret` and shift temp via `w0|=w3`/`w0<<=w2`), defeating the loop
    // convergence the kernel achieves by keeping those imprecise. Gate
    // on the SAME retval-enforcement condition zovia uses below (the
    // faithful mirror of "kernel reaches enforce_retval"). Per-path
    // lineage walk via parent_cache_id.
    let exit_enforces_retval = env.ctx.attach_flavor.as_deref() != Some("freplace")
        && (crate::ast::expected_retval_rule(
            env.ctx.prog_kind,
            env.ctx.attach_subtype.as_deref(),
        )
        .is_some()
            || env.ctx.prog_kind.requires_strict_return_code());
    if state.at_main_frame()
        && exit_enforces_retval
        && let Some(hidx) = state.history_idx
    {
        crate::analysis::flow::precision::mark_chain_precision_backward(env, hidx, state.parent_cache_id, Reg::R0);
    }

    // per-attach-type retval range. When a finer rule applies
    // for the (prog_kind, attach_subtype) pair, prefer it over the coarse
    // `requires_strict_return_code` check below — the kernel's per-hook
    // ranges are tighter (e.g. cgroup/recvmsg* must return exactly 1).
    // freplace EXT programs: skip both the per-attach-type retval rule
    // and the coarse `requires_strict_return_code` gate. The EXT's
    // return value is the *replaced subprog's* return (a regular `int`,
    // unconstrained), not the program's overall retval. Kernel verifier
    // skips `check_return_code`'s prog-type-specific range gates for
    // BPF_PROG_TYPE_EXT. Without this, freplace_connect_v4_prog
    // (returns 255 — out of cgroup/connect_v4's [0,1] rule) falsely
    // rejects.
    let is_freplace_ext = env.ctx.attach_flavor.as_deref() == Some("freplace");
    if state.at_main_frame() && !is_freplace_ext {
        if let Some(rule) = crate::ast::expected_retval_rule(
            env.ctx.prog_kind,
            env.ctx.attach_subtype.as_deref(),
        ) {
            // Kernel `check_return_code` uses `retval_range_s32` for
            // hooks whose retval is `int` — clang emits `return -EPERM`
            // as `w0 = 0xFFFFFFFF` (W32 mov), which zero-extends to
            // u64=4294967295 but reads as s32=-1. When the rule's lower
            // bound is negative (errno-style int return) and R0's full
            // s64 value sits cleanly in the [0, u32::MAX] band (zero-
            // extension of a 32-bit move), reinterpret the bounds in
            // s32. The kernel's `verifier.c` `retval_range_s32` does the
            // equivalent: it checks the s32 view of R0 against the
            // hook's s32 retval range. Closes
            // lsm.c::test_int_hook / test_bpf_cookie::test_int_hook /
            // iters_css_task::iter_css_task_for_each (`return -EPERM`).
            // For errno-style int retval rules (rule.lo < 0), prefer the
            // s32 view of R0 — the kernel's `retval_range_s32` checks
            // the s32 register width, not the u64 register. This handles
            // (a) `return -EPERM` (W32 mov of 0xFFFFFFFF: u64 = 4294967295,
            // s32 = -1) and (b) `return ret;` where `ret` was bounded
            // s64=[-4095, 0] at the entry-arg load but split to a
            // disjoint u64 set after W32 mov truncation. The s32 shadow
            // tracker preserves the [-4095, 0] view across the W32 mov.
            let (r0_lo_eff, r0_hi_eff) = if rule.lo < 0
                && rule.lo >= i32::MIN as i64
                && rule.hi <= i32::MAX as i64
            {
                let (s32_lo, s32_hi) = state.domain.get_s32_bounds(Reg::R0);
                (s32_lo as i64, s32_hi as i64)
            } else {
                (r0_min, r0_max)
            };
            let out_of_range = r0_lo_eff < rule.lo || r0_hi_eff > rule.hi;
            let needs_known = rule.require_known
                && (r0_min != r0_max
                    || state.types.get(Reg::R0) != RegType::ScalarValue);
            if out_of_range || needs_known {
                env.fail(VerificationError::InvalidReturnCode { pc: state.pc });
                return vec![];
            }
        } else if env.ctx.prog_kind.requires_strict_return_code()
            && (r0_min < 0 || r0_max > 1)
        {
            env.fail(VerificationError::InvalidReturnCode { pc: state.pc });
            return vec![];
        }
    }
    // Kernel `check_return_code` only fires at the *main* program's
    // exit — subprog (global_func) return values are unconstrained
    // (test_global_func8::foo returns `bpf_get_prandom_u32()` and
    // upstream accepts). Don't enforce the prog-type retval rule on
    // non-main exits.

    // R0 must be readable at the main frame (it's the return value).
    // void-returning struct_ops methods are exempt — the
    // kernel verifier doesn't require R0 to be set when the matched
    // ops-struct member's FUNC_PROTO declares a void return.
    if state.at_main_frame()
        && state.types.get(Reg::R0) == RegType::NotInit
        && !env.ctx.entry_returns_void
    {
        env.fail(VerificationError::RegisterNotReadable { pc, reg: Reg::R0 });
        return vec![];
    }

    // Check if there is any released reference
    if state.at_main_frame() && state.has_unreleased_refs() {
        warn!("Unreleased reference: {:?}", state.active_refs);
        env.fail(VerificationError::UnreleasedReference);
        return vec![];
    }

    // open-coded iterators must be destroyed on every exit path.
    // An Active or Drained iterator slot anywhere in the frame stack is
    // a leak — parallel to unreleased refs above.
    //
    // At main exit, walk all frames (defensive, though only frame[0] is
    // live then). At non-main exit (subprog return), check the current
    // frame: iter slots on the callee's stack vanish when the frame is
    // popped, so an undestroyed iter is a leak — kernel emits
    // "returning from callee: ... Unreleased reference".
    let iter_leak = if state.at_main_frame() {
        state.frames.iter().any(|f| f.stack.has_active_iterators())
    } else {
        state.frames.current().stack.has_active_iterators()
    };
    if iter_leak {
        env.fail(VerificationError::UnreleasedIterator);
        return vec![];
    }

    // ref-bearing dynptr slots (today: ringbuf reservations)
    // must be submitted or discarded on every exit path. Non-ref
    // dynptrs (Local/Skb/Xdp) are pure metadata over a pointer and
    // need no release. Same per-frame logic as iterators above.
    let dynptr_leak = if state.at_main_frame() {
        state
            .frames
            .iter()
            .any(|f| f.stack.has_unreleased_dynptr_refs())
    } else {
        state.frames.current().stack.has_unreleased_dynptr_refs()
    };
    if dynptr_leak {
        env.fail(VerificationError::UnreleasedDynptr);
        return vec![];
    }

    // Check if there is any unreleased locks. The kernel tracks a
    // single program-level active_lock, so a subprog `exit` may leave
    // the lock held for the caller to release (mirrors `verifier_spin_lock::
    // lock_in_subprog_without_unlock`). Only enforce at the main frame.
    if state.at_main_frame() && state.has_active_lock() {
        env.fail(VerificationError::UnreleasedLock);
        return vec![];
    }

    // Check if any RCU read-side section is still open. For
    // programs entered with the kernel's implicit RCU CS (kprobe,
    // tracepoint, raw_tp, perf_event), depth=1 at exit is the
    // kernel-supplied baseline — the kernel releases on return — so
    // tolerate it. Anything above 1 in that case, or anything > 0 in
    // sleepable / non-tracing programs, is an unreleased explicit
    // bpf_rcu_read_lock.
    //
    // Only enforce at main-frame exit. Subprog exits with an open RCU
    // CS are valid: the caller may have called bpf_rcu_read_lock and
    // expects the unlock either inside the subprog (e.g. rcu_read_lock_
    // subprog_unlock) or after the return (rcu_read_lock_subprog).
    // Kernel checks at the root frame's BPF_EXIT, mirroring
    // `check_lock` callers — same shape as the preempt/irq/lock
    // checks below this one.
    let baseline = if state.implicit_rcu_at_entry { 1 } else { 0 };
    if state.at_main_frame() && state.rcu_read_depth > baseline {
        env.fail(VerificationError::UnreleasedRcuRead);
        return vec![];
    }

    // Main-prog exit inside a preempt-disabled region (kernel verifier.c
    // v6.15 ~L11096). Subprog exits are fine: kernel only checks at the
    // root frame's BPF_EXIT, mirroring `check_lock` callers.
    if state.at_main_frame() && state.in_preempt_disabled() {
        env.fail(VerificationError::ExitInPreemptDisabled);
        return vec![];
    }

    // Main-prog exit inside an IRQ-disabled region (kernel verifier.c
    // v6.15 ~L11086). Same shape as the preempt check above. Subprog
    // exits are fine — kernel only checks at the root frame.
    if state.at_main_frame() && state.in_irq_disabled() {
        env.fail(VerificationError::IrqState {
            pc: state.pc,
            reason: "BPF_EXIT in main prog inside bpf_local_irq_save-ed region".into(),
        });
        return vec![];
    }
    // Also reject leaked irq flag stack slots (parallel to
    // has_active_iterators above).
    let irq_leak = if state.at_main_frame() {
        state.frames.iter().any(|f| f.stack.has_unreleased_irq_flags())
    } else {
        state.frames.current().stack.has_unreleased_irq_flags()
    };
    if irq_leak {
        env.fail(VerificationError::IrqState {
            pc: state.pc,
            reason: "leaked irq flag stack slot at exit".into(),
        });
        return vec![];
    }

    // Exit-time sanity guard: depth at exit shouldn't exceed the
    // kernel's MAX_CALL_FRAMES = 8. The pre-push `> 8` check in
    // `transfer_call_rel` already prevents pushing a 9th frame, so
    // hitting this at exit means a bug in frame bookkeeping. Use the
    // same `> 8` rule so a legitimate `main → 7 subprogs → exit`
    // chain (depth = 8 at the deepest) doesn't FR.
    if state.num_frames() > 8 {
        env.fail(VerificationError::MaxCallDepthExceeded { pc: state.pc });
        return vec![];
    }

    if !state.at_main_frame() && matches!(state.types.get(Reg::R0), RegType::PtrToStack { .. }) {
        env.fail(VerificationError::CannotReturnStackPointer { pc: state.pc });
        return vec![];
    }

    // a callback frame's Exit doesn't merge back into the caller
    // by way of CallRel return semantics — the helper's post-call state
    // is emitted separately at the call site (see
    // `transfer_callback_helper`'s skip_state). What we DO emit here
    // This is a SECOND post-call state at the call site's pc+1
    // that carries the cb's effects on caller-frame stack memory. This
    // mirrors the kernel's iterative cb model (verifier.c v6.15
    // ~L10903+): cb-touched scalar stack slots get widened on the
    // surviving caller state when the cb may run ≥ 2 times. For
    // nr_loops ≤ 1 (or single-shot helpers like find_vma) we keep the
    // cb's writes concretely, since there's no "previous iteration" to
    // widen against.
    if state.frames.current().is_callback() {
        if state.types.get(Reg::R0) != RegType::ScalarValue {
            env.fail(VerificationError::InvalidReturnCode { pc });
            return vec![];
        }
        // Kernel-aligned: callback return-value precision sink
        // (verifier.c v6.15 prepare_func_exit L10862). Per-path
        // lineage walk via parent_cache_id.
        if let Some(hidx) = state.history_idx {
            crate::analysis::flow::precision::mark_chain_precision_backward(env, hidx, state.parent_cache_id, Reg::R0);
        }
        // bpf_loop / bpf_for_each_map_elem / bpf_user_ringbuf_drain
        // callbacks must return 0 (continue) or 1 (break). Timer callbacks
        // are void-returning and not constrained here.
        let cb_helper_id = state.frames.current().callback_helper();
        if matches!(
            cb_helper_id,
            Some(crate::common::constants::BPF_LOOP)
                | Some(crate::common::constants::BPF_FOR_EACH_MAP_ELEM)
                | Some(crate::common::constants::BPF_USER_RINGBUF_DRAIN)
        ) {
            let (lo, hi) = state.domain.get_interval(Reg::R0);
            if lo < 0 || hi > 1 {
                env.fail(VerificationError::InvalidReturnCode { pc });
                return vec![];
            }
        }
        return cb_exit_propagate(env, state);
    }

    // Kernel: `bpf_update_live_stack(env)` before `prepare_func_exit`
    // (verifier.c:20664) — propagate the callee callchain's marks into
    // the caller's instance while the pre-pop callchain still exists —
    // and `bpf_reset_live_stack_callchain` (the write bracket no longer
    // matches the state's callchain, so this insn must not commit).
    {
        let ls_key = crate::analysis::flow::live_stack::callchain_of(&state);
        crate::analysis::flow::live_stack::update_live_stack(env, &ls_key);
        crate::analysis::flow::live_stack::invalidate_write_bracket(env);
    }
    if let Some(frame) = state.pop_frame() {
        // Save callee's R0 (the return value) before restoring caller state
        let ret_type = state.types.get(Reg::R0);
        let ret_tnum = state.get_tnum(Reg::R0);
        let ret_bounds = state.domain.get_interval(Reg::R0);
        let ret_anchor_info = state.save_anchor_info(Reg::R0);
        // Also save interval mode PtrOffset for packet pointer returns
        let ret_interval_ptr_offset = state.save_interval_ptr_offset(Reg::R0);

        // Save callee-saved registers' (R6-R9) packet range info.
        // These registers may have been updated by bounds checks in the callee.
        let callee_saved_packet_info: Vec<_> = [Reg::R6, Reg::R7, Reg::R8, Reg::R9]
            .iter()
            .map(|&r| (r, state.types.get(r), state.save_interval_ptr_offset(r)))
            .collect();

        // Save callee's anchor constraints before overwriting
        let callee_domain = state.domain.clone();

        let return_pc = frame.return_pc;
        state.types = frame.caller_types;
        state.domain = frame.caller_domain;
        state.tnums = frame.caller_tnums;

        // Restore the caller's R6-R9 bcf reg-expr bindings (kernel:
        // bcf_expr rides bpf_reg_state per-frame; the callee frame is
        // discarded at prepare_func_exit and the caller's regs — exprs
        // included — come back untouched). R0 keeps the CALLEE's binding
        // (caller->regs[BPF_REG_0] = *r0, verifier.c:11708). R1-R5 clear:
        // the caller's were scratched at the call insn
        // (clear_caller_saved_regs, verifier.c:11378 → mark_reg_not_init).
        if let Some(b) = state.bcf.as_mut() {
            if let Some(snap) = frame.caller_bcf_reg_snap.0 {
                for (i, r) in [Reg::R6, Reg::R7, Reg::R8, Reg::R9].iter().enumerate() {
                    if let Some(idx) = r.bcf_idx() {
                        b.restore_reg_binding(idx, snap[i]);
                    }
                }
            } else {
                for r in [Reg::R6, Reg::R7, Reg::R8, Reg::R9] {
                    if let Some(idx) = r.bcf_idx() {
                        b.clear_reg(idx);
                    }
                }
            }
            for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
                if let Some(idx) = r.bcf_idx() {
                    b.clear_reg(idx);
                }
            }
        }

        // Global-subprog isolation: restore the caller's rcu_read_depth
        // snapshot taken at push time. The body's bpf_rcu_read_lock /
        // _unlock calls are local to the global subprog's analysis and
        // must not leak into the caller's view (kernel verifies global
        // subprogs separately and treats their lock-state effects as
        // opaque). Closes
        // `rcu_read_lock.c::rcu_read_lock_global_subprog_unlock`.
        if let Some(snapshot) = frame.caller_rcu_read_depth_snapshot {
            state.rcu_read_depth = snapshot;
        }

        // Preserve anchor-to-anchor constraints from the callee.
        // These represent packet bounds (data/data_end/data_meta)
        // that were verified in the callee and remain valid.
        state.domain.preserve_anchor_constraints(&callee_domain);

        // If the callee's anchor constraints contradict the caller's saved
        // state, the path through the callee is infeasible from the caller's
        // context. Concretely: caller verified `data_end - data >= 82` along
        // its prefix, callee's exit path reached `data_end - data <= 53`
        // (an internal short-packet error branch). Both can't hold for the
        // same packet, so this exit edge is dead. Without dropping, repeated
        // `close()` passes downstream amplify the negative cycle into
        // garbage bounds (e.g. `r1 - 0 ≤ -875228325050`) which then mis-
        // route variable-offset / W32-truncation checks.
        if state.domain.is_inconsistent() {
            return vec![];
        }

        // Re-apply R0 from callee's return value
        state.types.set(Reg::R0, ret_type);
        state.set_tnum(Reg::R0, ret_tnum);
        state.domain.forget(Reg::R0);
        state
            .domain
            .assign_interval(Reg::R0, ret_bounds.0, ret_bounds.1);

        // Restore R0's anchor relationship (e.g., packet pointer offset from AnchorData)
        if let (Some(anchor), lo, hi) = ret_anchor_info {
            if let Some(h) = hi {
                state.domain.add_constraint(Reg::R0, anchor, h);
            }
            if let Some(l) = lo {
                state.domain.add_constraint(anchor, Reg::R0, l);
            }
            state.domain.close();
        }

        // Restore interval mode PtrOffset for packet pointer returns
        crate::analysis::transfer::call::transfer::restore_interval_ptr_offset_from_return(
            &mut state.domain,
            &ret_type,
            ret_interval_ptr_offset,
        );

        // Restore callee-saved registers' (R6-R9) packet range info.
        // If a bounds check in the callee proved range for these registers,
        // we need to carry that forward to the caller.
        crate::analysis::transfer::call::transfer::restore_callee_interval_packet_info(
            &mut state.domain,
            &state.types,
            callee_saved_packet_info,
        );

        state.types.set(
            Reg::R10,
            RegType::PtrToStack {
                frame_level: state.current_frame_level(),
            },
        );
        state.pc = return_pc;
        vec![state]
    } else {
        vec![]
    }
}

/// Build a post-cb state at the helper call's pc+1 that carries the
/// cb's effects on caller-frame memory. Mirrors kernel's
/// `prepare_func_exit` cb-return path + `widen_imprecise_scalars`
/// (verifier.c v6.15 ~L10898–10920). Caller-frame stack writes done
/// via the cb's ctx pointer have already landed on the right frame
/// (PtrToStack carries frame_level); we pop the cb frame, restore
/// caller regs, and—if the cb may iterate ≥ 2 times—invalidate the
/// stack slots that differ from the snapshot taken at cb-entry.
fn cb_exit_propagate(env: &VerifierEnv, mut state: State) -> Vec<State> {
    use crate::analysis::machine::frame_stack::FrameLevel;
    use crate::analysis::machine::reg_types::RegType;
    use crate::analysis::transfer::call::transfer::apply_return_bounds_for_cb_helper;
    use crate::domains::tnum::Tnum;
    use std::collections::HashSet;

    let Some(frame) = state.pop_frame() else {
        return vec![];
    };
    let return_pc = frame.return_pc;
    let helper = frame.callback_helper().unwrap_or(0);
    let should_widen = frame.cb_should_widen();
    let caller_level = frame.caller_frame_level();
    let snapshot = frame.caller_stack_snapshot().cloned();
    let cb_writeable: Vec<i16> = frame.cb_writeable_caller_offsets().to_vec();

    // Restore caller regs (cb's R0 etc. are dropped).
    state.types = frame.caller_types;
    state.domain = frame.caller_domain;
    state.tnums = frame.caller_tnums;

    // Caller bcf reg bindings: R6-R9 from the push-time snapshot (per-frame
    // bcf_expr, see transfer_exit's pop above); R0-R5 clear — the helper
    // call that entered this callback scratches caller-saved regs
    // (check_helper_call mark_reg_not_init, verifier.c:12370-12373).
    if let Some(b) = state.bcf.as_mut() {
        if let Some(snap) = frame.caller_bcf_reg_snap.0 {
            for (i, r) in [Reg::R6, Reg::R7, Reg::R8, Reg::R9].iter().enumerate() {
                if let Some(idx) = r.bcf_idx() {
                    b.restore_reg_binding(idx, snap[i]);
                }
            }
        } else {
            for r in [Reg::R6, Reg::R7, Reg::R8, Reg::R9] {
                if let Some(idx) = r.bcf_idx() {
                    b.clear_reg(idx);
                }
            }
        }
        for r in [Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
            if let Some(idx) = r.bcf_idx() {
                b.clear_reg(idx);
            }
        }
    }

    // Helper return value lives in R0; bounds depend on helper kind.
    state.types.set(Reg::R0, RegType::ScalarValue);
    apply_return_bounds_for_cb_helper(&mut state, helper);
    state.clear_scalar_id(Reg::R0);

    // Forget arg regs (helpers clobber R1..R5).
    for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
        state.types.set(r, RegType::ScalarValue);
        state.domain.forget(r);
        state.set_tnum(r, Tnum::unknown());
        state.clear_scalar_id(r);
    }

    // Apply widening to caller-frame stack slots the cb touched. We
    // detect "touched" by comparing each slot against the pre-cb
    // snapshot. With cb_should_widen=false (nr_loops ≤ 1, find_vma)
    // we keep the cb's writes concretely; this lets `_ok`-style tests
    // verify with the post-cb concrete value while still abstracting
    // multi-iteration cases.
    if should_widen
        && let (Some(snap), Some(idx)) = (snapshot, caller_level)
    {
        let caller_stack = state.stack_at_mut(FrameLevel::from_index(idx));
        let mut all_offsets: HashSet<i16> = snap.slot_offsets().into_iter().collect();
        all_offsets.extend(caller_stack.slot_offsets());
        for off in all_offsets {
            let snap_slot = snap.get_slot(off);
            let cur_slot = caller_stack.get_slot(off);
            let differs = match (snap_slot, cur_slot) {
                (None, None) => false,
                (None, Some(_)) | (Some(_), None) => true,
                (Some(a), Some(b)) => a != b,
            };
            if differs {
                caller_stack.invalidate_slot(off);
            }
        }
        // Also invalidate every slot the cb body could write through
        // its ctx-pointer on ANY branch (pre-computed at env init via
        // static scan). This is the kernel's multi-iteration cb model:
        // when nr_loops > 1, different cb branches can fire on
        // different iterations, so the post-loop continuation must
        // reflect the union of all branches' effects (verifier.c v6.15
        // ~L10903 widen_imprecise_scalars over iter-state). Without
        // this, single-branch cb-exits leave non-this-branch slots
        // concrete and the continuation falsely accepts patterns that
        // require interleaved iterations (`iter_limit_bug`).
        for off in cb_writeable {
            caller_stack.invalidate_slot(off);
        }
    }

    state.pc = return_pc;

    // cb-return widener (kernel verifier.c v6.15 ~L10903-10920):
    //   prev_st = in_callback_fn ? find_prev_entry(env, state, *insn_idx) : NULL;
    //   if (prev_st)
    //       widen_imprecise_scalars(env, prev_st, state);
    //
    // The snapshot-based widening above widens stack
    // slots the cb wrote during THIS iteration. The kernel additionally
    // runs `widen_imprecise_scalars` between this post-cb state and a
    // PRIOR post-cb visit at the same continuation pc — coarsening
    // values that differ across iterations of a multi-iteration helper
    // (bpf_loop, bpf_for_each_map_elem). This is the same machinery
    // already wired at iter_next and may_goto.
    //
    // Gated on `should_widen` (set when nr_loops > 1 at the helper call
    // site). For nr_loops ≤ 1 (or single-shot helpers like find_vma) the
    // cb runs once; widening between successive call sites would
    // destroy precision the test relies on (e.g.
    // `bpf_loop_iter_limit_nested` enumerates exact post-cb values).
    //
    // Skip-cur logic mirrors the may_goto site: record_state precedes
    // transfer in the worklist driver, so the most recent cached state
    // at `return_pc` is the just-recorded current state — skip it and
    // take the previous one.
    if should_widen {
        let prev_clone: Option<State> = env.explored_states.get(&return_pc).and_then(|prev_states| {
            let mut iter = prev_states.iter().rev().filter(|s| s.pc == return_pc);
            iter.next();
            iter.next().cloned()
        });
        if let Some(prev) = prev_clone.as_ref() {
            crate::analysis::transfer::call::kfunc::widen_imprecise_scalars_at_iter_next(
                env, prev, &mut state,
            );
        }
    }

    vec![state]
}
