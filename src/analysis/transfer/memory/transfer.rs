use crate::analysis::machine::error::VerificationError;
// src/analysis/transfer/memory/transfer.rs

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use crate::ast::{AtomicOp, MemSize, Operand};
use crate::domains::tnum::Tnum;

use super::access::{self};
use crate::analysis::transfer::common::{
    check_operand_readable, check_reg_readable, check_reg_writable,
};
use crate::analysis::transfer::types::{update_load_types, update_store_types};

pub(crate) fn transfer_load(
    env: &mut VerifierEnv,
    mut state: State,
    size: MemSize,
    dst: Reg,
    base: Reg,
    off: i16,
) -> Vec<State> {
    if !check_reg_readable(env, &mut state, base) {
        return vec![];
    }
    if !check_reg_writable(env, &state, dst) {
        return vec![];
    }

    // A load fully redefines dst; any prior BTF field-offset tracking
    // (from earlier ptr-arith on this register) becomes stale and would
    // mislead the helper-arg bounds-checker.
    state.btf_field_refs.remove(&dst);
    // Loads also clear the kernel-tnum-imprecision flag — the loaded
    // value is fresh from memory, with whatever bounds we infer from
    // the access width, not from any prior chain through DIV/MOD.
    state.kernel_tnum_imprecise.remove(&dst);
    // Kernel: every non-fill load lands in `mark_reg_unknown`, which
    // zeroes `reg->id` — a freshly loaded value never inherits the old
    // register's scalar-equivalence class (otherwise a later branch
    // refinement via the `sync_linked_regs` mirror would fan out into
    // slots/regs holding unrelated older values). The stack-fill path
    // below re-installs the SLOT's saved id (kernel copy_register_state
    // on fill), so clearing first is kernel order.
    state.clear_scalar_id(dst);
    // BCF: a load is a full register write; clear any prior `bcf_expr`
    // so future uses lazy-materialize against the post-load bounds
    // rather than dragging in a stale pre-load expression (e.g. an
    // earlier `Mov r8, 0` cache hit). Mirrors kernel BCF's
    // `reg->bcf_expr = -1` on clobbering writes
    // (verifier.c `bcf_mov32`
    // analog at the post-load reset point).
    if let Some(idx) = dst.bcf_idx()
        && let Some(bcf) = state.bcf.as_mut()
    {
        bcf.clear_reg(idx);
    }

    let access_size = size.bytes() as i64;
    access::check_load(env, &state, base, access_size, off);

    // BCF set6 `detect_conflict_eq`: `check_load` proved this path's
    // path_conds syntactically contradictory. Drop the path with no
    // successors — the analog of the kernel's `goto process_bpf_exit`
    // after `bcf->path_unreachable`.
    if env.bcf_path_unreachable {
        env.bcf_path_unreachable = false;
        return vec![];
    }

    if try_load_from_rodata(env, &mut state, dst, base, off, size) {
        state.pc += 1;
        return vec![state];
    }

    if let RegType::PtrToStack { frame_level } = state.types.get(base)
        && let Some(base_off) = state.domain.get_distance_fixed(base, Reg::R10)
    {
        let slot_off = off + base_off as i16;
        // Kernel `INSN_F_STACK_ACCESS` for a fill
        // (`check_stack_read_fixed_off`): kept only when the slot
        // `is_spilled_reg` — it actually held a spilled register.
        // alivio's `SpilledReg.source_reg.is_some()` is that exact
        // predicate (symmetric with the spill side above), so a read of
        // plain stack data (no spilled reg in the slot) is *not* tagged
        // and the backtrack stops there.
        let slot_is_spilled_reg = state
            .stack_at(frame_level)
            .get_slot(slot_off)
            .is_some_and(|s| s.source_reg.is_some());
        if state.fill_at(frame_level, dst, slot_off, size) {
            // Kernel check_mem_access tail (verifier.c:8292-8296) runs
            // AFTER the PTR_TO_STACK dispatch too: every sub-8-byte
            // scalar READ zero-extends — coerce_reg_to_size does
            // `var_off = tnum_cast(var_off, size)` (upper bits known 0).
            // The generic-load tail below mirrors it for non-stack
            // loads; apply it on the fill early-return too so e.g. a u8
            // read of a STACK_MISC byte gets tnum (0;0xff).
            if access_size < 8 && matches!(state.types.get(dst), RegType::ScalarValue) {
                let m = (1u64 << (access_size as u32 * 8)) - 1;
                let t = state.get_tnum(dst);
                state.set_tnum(
                    dst,
                    crate::domains::tnum::Tnum {
                        value: t.value & m,
                        mask: t.mask & m,
                    },
                );
            }
            // Kernel-faithful: spill/fill saves and restores the full
            // bpf_reg_state. alivio's slot doesn't carry ptr_const_off or
            // var_off_contributor, so clear them for `dst` on fill to
            // match the kernel's "fresh value" semantics; a proper fix
            // would preserve them through slot metadata.
            state.ptr_const_off.remove(&dst);
            state.var_off_contributor.remove(&dst);
            if let Some(idx) = env.current_step_idx
                && slot_is_spilled_reg
                && !env.replay_mode
            {
                env.history.set_stack_access(idx);
            }
            state.pc += 1;
            return vec![state];
        }
    }

    let bounds_set = update_load_types(env, &mut state, access_size as usize, dst, base, off);
    if !bounds_set {
        // Default post-load: forget any prior dst bounds and re-clamp to
        // the access width's zero-extended range. Skipped when
        // `update_load_types` returned `true`, signaling it already
        // installed an explicit numeric bound (e.g. LSM int-hook
        // `BoundedScalar` ctx-arg load — the bound there is tighter than
        // the access width's clamp would be, and the s32 shadow we set
        // would be lost).
        state.domain.forget(dst);

        match size {
            MemSize::U8 => {
                state.domain.assume_ge_imm(dst, 0);
                state.domain.assume_le_imm(dst, 0xFF);
            }
            MemSize::U16 => {
                state.domain.assume_ge_imm(dst, 0);
                state.domain.assume_le_imm(dst, 0xFFFF);
            }
            MemSize::U32 => {
                state.domain.assume_ge_imm(dst, 0);
                state.domain.assume_le_imm(dst, 0xFFFFFFFF);
            }
            MemSize::U64 => {}
        }
    }

    match state.types.get(dst) {
        RegType::PtrToPacket => {
            state.domain.bind_to_anchor(dst, Reg::AnchorData);
        }
        RegType::PtrToPacketMeta => {
            state.domain.bind_to_anchor(dst, Reg::AnchorDataMeta);
        }
        RegType::PtrToPacketEnd => {
            state.domain.bind_to_anchor(dst, Reg::AnchorDataEnd);
        }
        _ => {}
    }

    // Kernel check_mem_access tail (verifier.c:8291-8296): every
    // sub-8-byte scalar READ zero-extends — "b/h/w load zero-extends,
    // mark upper bits as known 0" via coerce_reg_to_size →
    // reg->var_off = tnum_cast(var_off, size). Guard on SCALAR dst like
    // the kernel condition does — 32-bit ctx loads of rewritten pointer
    // fields (skb->data etc.) leave a 64-bit pointer in dst and must
    // not get a 32-bit-masked tnum.
    if matches!(state.types.get(dst), RegType::ScalarValue) {
        state.set_tnum(dst, Tnum::unknown_bits(access_size as u32 * 8));
    } else {
        state.set_tnum(dst, Tnum::unknown());
    }
    state.pc += 1;
    vec![state]
}

/// Sign-extending load (LDSX, v6.6).
///
/// Semantically: load `size` bytes from `[base + off]` and sign-extend the
/// result to 64 bits in `dst`. Access checks (readability of base, type-of-ptr
/// rules, stack fills, fault reporting) mirror a regular load; the only
/// difference is the bounds we assign to `dst` after the load. Instead of the
/// unsigned [0, 2^n - 1] range that a zero-extending load produces, LDSX
/// produces a two's-complement sign-extended value in the range
/// [-(2^(n-1)), 2^(n-1) - 1].
///
/// Precision loss: we always forget `dst` and re-clamp, even on stack-fill
/// paths where a constant value might otherwise be preserved. Threading the
/// sign extension through every fill path is future work; correctness is
/// the priority here.
pub(crate) fn transfer_load_sx(
    env: &mut VerifierEnv,
    state: State,
    size: MemSize,
    dst: Reg,
    base: Reg,
    off: i16,
) -> Vec<State> {
    let (lo, hi) = match size {
        MemSize::U8 => (i8::MIN as i64, i8::MAX as i64),
        MemSize::U16 => (i16::MIN as i64, i16::MAX as i64),
        MemSize::U32 => (i32::MIN as i64, i32::MAX as i64),
        // LDSX DW doesn't exist in the ISA; decode rejects it. Defensive clamp.
        MemSize::U64 => (i64::MIN, i64::MAX),
    };

    let origin_pc = state.pc;
    let mut results = transfer_load(env, state, size, dst, base, off);

    // LDSX of a location that would yield a pointer (e.g. __sk_buff->data via
    // ctx narrow-load, or a spilled pointer on stack) is rejected by the
    // kernel verifier: sign-extending a pointer produces meaningless bits.
    let any_ptr_load = results
        .iter()
        .any(|s| !matches!(s.types.get(dst), RegType::ScalarValue | RegType::NotInit));
    if any_ptr_load {
        env.fail(VerificationError::UnsupportedModernFeature {
            pc: origin_pc,
            feature: "LDSX of a pointer-typed field",
        });
        return vec![];
    }

    for s in results.iter_mut() {
        s.types.set(dst, RegType::ScalarValue);
        s.domain.forget(dst);
        s.domain.assume_ge_imm(dst, lo);
        s.domain.assume_le_imm(dst, hi);
        s.set_tnum(dst, Tnum::unknown());
    }
    results
}

pub(crate) fn transfer_store(
    env: &mut VerifierEnv,
    mut state: State,
    size: MemSize,
    base: Reg,
    off: i16,
    src: &Operand,
) -> Vec<State> {
    if !check_reg_readable(env, &mut state, base) {
        return vec![];
    }
    if !check_operand_readable(env, &mut state, src) {
        return vec![];
    }

    // Kernel `__check_reg_arg` SRC_OP hook (verifier.c ~4091): during
    // bcf_track, EVERY read of a non-const register materializes its
    // VAR + bound block ("Bind an expr for non-constants when it's
    // first used") — including the store-source read here, so e.g. a u8
    // load stored to a map value contributes its `u<= 0xff` bound var
    // to the replay goal. reg_expr is first-ref-cached (kernel
    // `reg->bcf_expr >= 0` out), so a later spill/cond reference of the
    // same reg dedups.
    if env.replay_mode
        && let Operand::Reg(r) = src
        && matches!(state.types.get(*r), RegType::ScalarValue)
        && let Some(src_idx) = r.bcf_idx()
        && state.bcf.is_some()
    {
        let bounds = crate::analysis::transfer::alu::helpers::bcf_reg_bounds(&state, *r);
        // Kernel gate: `!tnum_is_const(reg->var_off)` — consts are not
        // materialized at the read hook.
        if bounds.const_val.is_none() {
            let pc = state.pc;
            if let Some(b) = state.bcf.as_mut() {
                b.set_current_pc(pc);
                b.reg_expr(src_idx, &bounds, false);
            }
        }
    }

    let access_size = size.bytes() as i64;
    let src_type = match src {
        Operand::Reg(r) => state.types.get(*r),
        Operand::Imm(_) => RegType::ScalarValue,
    };

    access::check_store(env, &state, base, access_size, off, src_type);

    // Stores to an Unref kptr slot accept only NULL (proven zero) or a
    // fresh acquired pointer (PtrToBtfId / PtrToMapKptr / PtrToOwnedKptr).
    // A pointer that has had ALU applied to it lands in `ScalarValue`
    // (the default arm of `update_ptr_arithmetic_type`), so checking
    // src_type for non-pointer-non-zero closes the variable-offset and
    // bad-arithmetic store cases. Kernel diagnostic family:
    // "variable untrusted_ptr_ access var_off=(...)".
    if !env.failed()
        && let RegType::PtrToMapValue {
            offset: map_off,
            map_idx,
            ..
        } = state.types.get(base)
        && let Some(map_def) = env.ctx.map_defs.get(map_idx)
        && let Some(off_val) = super::map::resolve_const_map_off(&state, base, map_off, off)
        && let Some(field) = super::map::kptr_field_at(map_def, off_val, access_size)
    {
        use crate::parsing::elf::KptrFieldKind;
        if matches!(field.kind, KptrFieldKind::Unref) {
            let src_is_zero = match src {
                Operand::Imm(v) => *v == 0,
                Operand::Reg(r) => {
                    matches!(src_type, RegType::ScalarValue) && state.domain.proven_zero(*r)
                }
            };
            // Stored kptr value must have zero offset — kernel
            // "invalid kptr access, R1 type=untrusted_ptr_..." rejects
            // a kptr loaded from a slot, bumped by `+ K`, and stored
            // back (`reject_bad_type_match` in map_kptr_fail.c).
            // PtrToOwnedKptr never appears as a kptr-store source in
            // realistic programs (alloc'd objects pass through xchg,
            // not direct store), so a present-but-non-zero offset on
            // any of these variants signals the bad-arith pattern.
            let src_is_acquired_ptr = match src_type {
                RegType::PtrToBtfId { .. } => true,
                // Specialized kernel-struct pointers (returned by helpers
                // like bpf_get_current_task_btf, bpf_task_from_pid,
                // bpf_cpumask_*) are equivalent to PtrToBtfId{<name>} for
                // kptr-store purposes. Closes lru_bug.c::nanosleep
                // (`v->ptr = bpf_get_current_task_btf()` into a
                // `__kptr_untrusted task_struct *` field).
                RegType::PtrToTask { .. }
                | RegType::PtrToCgroup { .. }
                | RegType::PtrToCpumask { .. } => true,
                RegType::PtrToMapKptr { offset, .. }
                | RegType::PtrToMapKptrOrNull { offset, .. } => offset == 0,
                RegType::PtrToOwnedKptr { offset, .. } => offset == 0,
                RegType::PtrToOwnedKptrOrNull { offset, .. } => offset == 0,
                _ => false,
            };
            if !src_is_zero && !src_is_acquired_ptr {
                env.fail(VerificationError::InvalidArgType {
                    pc: state.pc,
                    reg: match src {
                        Operand::Reg(r) => *r,
                        Operand::Imm(_) => Reg::R0,
                    },
                });
                return vec![];
            }
        }
    }

    let base_type = state.types.get(base);
    if let RegType::PtrToStack { frame_level } = base_type {
        if let Some(base_off) = state.domain.get_distance_fixed(base, Reg::R10) {
            let full_offset = base_off + off as i64;
            // a stack write that overlaps any byte of an active
            // ref-bearing dynptr (today: ringbuf reservations) is the
            // kernel's "cannot overwrite referenced dynptr" rejection.
            // Allowed for unreferenced dynptrs (Local/Skb/Xdp) — but
            // the kernel still tears down the dynptr and invalidates
            // any slices tagged with its `dynptr_id`
            // (`destroy_if_dynptr_stack_slot`, verifier.c v6.15 L880).
            // Without this destroy step, a slice taken via
            // `bpf_dynptr_data` survives a corrupting partial write to
            // the dynptr metadata and a later `*slice` deref leaks
            // through.
            if state
                .stack_at(frame_level)
                .write_overlaps_referenced_dynptr(full_offset, size.bytes() as i64)
            {
                env.fail(VerificationError::DynptrOverwrite {
                    pc: state.pc,
                    off: full_offset,
                });
                return vec![];
            }
            let touched_dynptrs = state
                .stack_at(frame_level)
                .dynptr_pairs_touched_by_write(full_offset, size.bytes() as i64);
            if !touched_dynptrs.is_empty() {
                let stack = state.stack_at_mut(frame_level);
                for (base_off, _) in &touched_dynptrs {
                    stack.stack_clear_dynptr(*base_off);
                    stack.stack_clear_dynptr(*base_off + 8);
                }
                for (_, vid) in &touched_dynptrs {
                    state.invalidate_dynptr_slices(*vid);
                }
            }
            // same shape for open-coded iterators. Iter bodies
            // are opaque — only `*_new`/`*_next`/`*_destroy` may write
            // them. Without this, `spill_at` silently wipes the iter
            // annotation and a missing destroy slips by the exit-time
            // `has_active_iterators` leak check.
            if state
                .stack_at(frame_level)
                .access_overlaps_iterator(full_offset, size.bytes() as i64)
            {
                env.fail(VerificationError::IteratorOverwrite {
                    pc: state.pc,
                    off: full_offset,
                });
                return vec![];
            }
            // Same shape for IRQ flag slots — direct writes destroy the
            // STACK_IRQ_FLAG mark; without this check, a missing
            // `bpf_local_irq_restore` slips by the exit-time leak check
            // (irq_flag_overwrite{,_partial} corpus tests).
            if state
                .stack_at(frame_level)
                .access_overlaps_irq_flag(full_offset, size.bytes() as i64)
            {
                env.fail(VerificationError::IrqFlagOverwrite {
                    pc: state.pc,
                    off: full_offset,
                });
                return vec![];
            }
            match src {
                Operand::Reg(r) => {
                    // Kernel check_stack_write_fixed_off STACK_ZERO rule:
                    // storing a known-null reg on the MISC/ZERO path (an
                    // unaligned or non-spillable store) runs the FULL
                    // `mark_chain_precision(value_regno)` backward walk —
                    // "backtrack the register to make sure it's a known
                    // zero". spill_at's local precise_regs mark alone
                    // never reaches CACHED ancestors, so run the walk.
                    let is_aligned = full_offset % 8 == 0;
                    let is_scalar = matches!(
                        state.types.get(*r),
                        crate::analysis::machine::reg_types::RegType::ScalarValue
                    );
                    let zero_path = !(is_aligned && (is_scalar || size == MemSize::U64));
                    if zero_path
                        && is_scalar
                        && state.domain.proven_zero(*r)
                        && let Some(hidx) = state.history_idx
                    {
                        crate::analysis::flow::precision::mark_chain_precision_backward(
                            env,
                            hidx,
                            state.parent_cache_id,
                            *r,
                        );
                    }
                    state.spill_at(frame_level, *r, full_offset as i16, size);
                }
                Operand::Imm(k) => {
                    state.store_imm_to_stack_at(frame_level, *k, full_offset as i16, size);
                }
            }
            // Kernel `bpf_mark_stack_write` (check_stack_write_fixed_off,
            // verifier.c:5599): only a FULL 8-byte aligned write marks the
            // slot written — partial writes leave read propagation
            // conservative (the slot stays live across them).
            if full_offset % 8 == 0
                && size == MemSize::U64
                && let Some(spi) = crate::analysis::flow::live_stack::spi_of(full_offset)
            {
                crate::analysis::flow::live_stack::mark_stack_write(
                    env,
                    frame_level.index(),
                    1u64 << spi,
                );
            }
            // Kernel `INSN_F_STACK_ACCESS` for a spill
            // (`check_stack_write_fixed_off`): a slot-aligned scalar /
            // BPF_ST-const / 8-byte-pointer register spill. alivio's
            // `spill_at`/`store_imm_to_stack_at` already encode exactly
            // that gate as `SpilledReg.source_reg.is_some()` (set iff
            // `off % 8 == 0`; see stack_ops.rs comments citing
            // verifier.c:5598). Back-patch the breadcrumb so the
            // backtrack walk follows this slot the same way the kernel's
            // `backtrack_insn` does on `hist->flags & INSN_F_STACK_ACCESS`
            // — and *only* this slot, not every slot-aligned data write.
            if let Some(idx) = env.current_step_idx
                && state
                    .stack_at(frame_level)
                    .get_slot(full_offset as i16)
                    .is_some_and(|s| s.source_reg.is_some())
            {
                env.history.set_stack_access(idx);
            }
            state.update_frame_depth(off);
            update_store_types(
                state.stack_at_mut(frame_level),
                src_type,
                size,
                Some(full_offset),
            );
        } else {
            let (lo, hi) = state.domain.get_distance_interval(base, Reg::R10);
            if lo != i64::MIN && hi != i64::MAX {
                let min_slot = lo + off as i64;
                let max_slot = hi + off as i64 + size.bytes() as i64;
                let stack = state.stack_at_mut(frame_level);
                for slot in min_slot..max_slot {
                    stack.invalidate_slot(slot as i16);
                }
            }
            state.update_frame_depth(off);
        }
    }

    state.pc += 1;
    vec![state]
}

pub(crate) fn transfer_atomic(
    env: &mut VerifierEnv,
    mut state: State,
    op: AtomicOp,
    fetch: bool,
    size: MemSize,
    base: Reg,
    off: i16,
    src: Reg,
) -> Vec<State> {
    if off % size.bytes() as i16 != 0 {
        env.fail(VerificationError::MisalignedAccess {
            pc: state.pc,
            off: off.into(),
        });
        return vec![];
    }

    if !check_reg_readable(env, &mut state, base) {
        return vec![];
    }
    if !check_reg_readable(env, &mut state, src) {
        return vec![];
    }
    if op == AtomicOp::CmpXchg && !check_reg_readable(env, &mut state, Reg::R0) {
        return vec![];
    }

    if op == AtomicOp::CmpXchg {
        if !check_reg_writable(env, &state, Reg::R0) {
            return vec![];
        }
    } else if fetch && !check_reg_writable(env, &state, src) {
        return vec![];
    }

    let base_ty = state.types.get(base);
    if matches!(base_ty, RegType::PtrToCtx) {
        env.fail(VerificationError::InvalidArgType {
            pc: state.pc,
            reg: base,
        });
        return vec![];
    }

    let access_size = size.bytes() as i64;
    access::check_load(env, &state, base, access_size, off);
    if env.bcf_path_unreachable {
        env.bcf_path_unreachable = false;
        return vec![];
    }
    access::check_store(env, &state, base, access_size, off, state.types.get(src));
    if env.failed() {
        return vec![];
    }

    let reloaded = if op == AtomicOp::CmpXchg {
        state.fill(Reg::R0, off, size)
    } else if fetch {
        state.fill(src, off, size)
    } else {
        false
    };

    let resolved_offset = if matches!(base_ty, RegType::PtrToStack { .. }) {
        state
            .domain
            .get_distance_fixed(base, Reg::R10)
            .map(|o| o + off as i64)
    } else {
        None
    };
    update_store_types(
        state.stack_mut(),
        RegType::ScalarValue,
        size,
        resolved_offset,
    );
    if base == Reg::R10 {
        state.stack_mut().invalidate_slot(off);
    }

    if op == AtomicOp::CmpXchg {
        if !reloaded {
            state.domain.forget(Reg::R0);
            state.set_tnum(Reg::R0, Tnum::unknown());
        }
    } else if fetch && !reloaded {
        state.domain.forget(src);
        state.set_tnum(src, Tnum::unknown());
    }

    if base == Reg::R10 {
        state.update_frame_depth(off);
    }

    state.pc += 1;
    vec![state]
}

pub fn try_load_from_rodata(
    env: &VerifierEnv,
    state: &mut State,
    dst: Reg,
    base: Reg,
    insn_off: i16,
    size: MemSize,
) -> bool {
    if let RegType::PtrToMapValue {
        id: _,
        map_idx,
        offset: base_offset,
        ..
    } = state.types.get(base)
        && let Some(ptr_val) = base_offset
    {
        let map = &env.ctx.map_defs[map_idx];

        // Kernel-aligned: only constant-fold reads from frozen rodata
        // maps (`bpf_map_is_rdonly`, verifier.c v6.15 L6928). `.data` and
        // `.bss` may have an `initial_data` blob from the ELF, but they
        // are read-write from the program's perspective and from
        // userspace; the kernel does NOT mark loads from them as known
        // constants. Folding them here defeats the `int i = zero`
        // obfuscation pattern that selftests use to keep loop counters
        // imprecise (see iters.c:iter_obfuscate_counter test comment).
        if (map.map_flags & crate::common::constants::BPF_F_RDONLY_PROG) == 0 {
            return false;
        }

        if let Some(data) = &map.initial_data {
            let abs_off = ptr_val + insn_off as i64;

            if abs_off >= 0 {
                let start = abs_off as usize;
                let len = size.bytes();

                if start + len <= data.len() {
                    let bytes = &data[start..start + len];

                    let mut val: u64 = 0;
                    for (i, &b) in bytes.iter().enumerate() {
                        val |= (b as u64) << (i * 8);
                    }

                    state.domain.forget(dst);
                    state.domain.assume_eq_imm(dst, val as i64);
                    state.types.set(dst, RegType::ScalarValue);
                    // Pin tnum to the loaded constant too. Kernel's
                    // `bpf_map_is_rdonly` path produces a fully-known
                    // tnum (`tnum_const(val)`). Without this the next
                    // bitwise/ALU op (e.g. `r &= 1` to test a low bit)
                    // collapses the constant: handle_and does
                    // forget(dst) then apply_and_imm which only sets
                    // [0, mask], and tnum.and_imm(mask) on unknown tnum
                    // never becomes constant — so the conditional
                    // branch on the result splits both ways and dead
                    // loop bodies (`while (*p & 1)` over rodata=2)
                    // get explored. Mirrors kernel verifier.c v6.15
                    // L6928 (`bpf_map_direct_read`).
                    state.set_tnum(dst, Tnum::constant(val));

                    return true;
                }
            }
        }
    }
    false
}
