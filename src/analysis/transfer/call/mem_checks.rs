// src/analysis/transfer/call/mem_checks.rs
//
// Memory-access validation for BPF helper and kfunc arguments.
// Validates readable/writable memory ranges, mem+size pairs, and
// pointer-to-map/stack/packet bounds checks.

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::error::VerificationError;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::{RegType, TypeState};
use crate::analysis::machine::state::State;
use crate::analysis::transfer::memory::access::{self, AccessKind};
use crate::analysis::transfer::memory::{
    check_kptr_field_access, check_map_access, check_map_rw, check_packet_access,
    check_stack_access, check_stack_arg_readable,
};
use crate::common::constants;
use log::error;

use super::signatures::{ArgKind, CallProto, MemSizePair};

// ============================================================================
// Memory Validation Helpers
// ============================================================================

/// Validates that a register points to readable memory.
pub(crate) fn validate_readable_mem(
    env: &mut VerifierEnv,
    state: &State,
    pc: usize,
    reg: Reg,
    reg_type: RegType,
    size: Option<u32>,
) -> bool {
    match reg_type {
        RegType::PtrToStack { .. } => {
            if let Some(off) = state.domain.get_distance_fixed(reg, Reg::R10) {
                if let Some(sz) = size {
                    check_stack_arg_readable(
                        env,
                        state,
                        off,
                        sz as i64,
                        pc,
                        AccessKind::HelperBuffer,
                    );
                }
                true
            } else {
                // Variable stack offset — use bounds check
                if let Some(sz) = size {
                    let (lo, hi) = state.domain.get_distance_interval(reg, Reg::R10);
                    if lo != i64::MIN && hi != i64::MAX {
                        // Check all possible offsets in the range
                        for off_candidate in lo..=hi {
                            check_stack_arg_readable(
                                env,
                                state,
                                off_candidate,
                                sz as i64,
                                pc,
                                AccessKind::HelperBuffer,
                            );
                            if env.failed() {
                                return false;
                            }
                        }
                        true
                    } else {
                        env.fail(VerificationError::UninitializedStackRead { pc, offset: 0 });
                        false
                    }
                } else {
                    true
                }
            }
        }
        // Delegate the checking for these to access.rs
        RegType::PtrToMapValue { map_idx, .. } => {
            if let Some(size) = size {
                access::check_load(env, state, reg, size as i64, 0);
                if env.failed() {
                    return false;
                }
                true
            } else {
                check_map_rw(env, map_idx, pc, false);
                if env.failed() {
                    return false;
                }
                true
            }
        }
        RegType::PtrToPacket | RegType::PtrToPacketMeta => {
            if let Some(size) = size {
                access::check_load(env, state, reg, size as i64, 0);
                if env.failed() {
                    return false;
                }
                true
            } else {
                true
            }
        }
        RegType::PtrToCtx => {
            // Context can be read
            true
        }
        // Ring-buffer reservations (`bpf_ringbuf_reserve`) and arena
        // allocations carry their own bounds in `mem_size`. Kernel
        // accepts these as ARG_PTR_TO_MEM (mirrors `verifier_ringbuf::
        // passing_rb_mem_to_helpers`, which routes ringbuf-reserved
        // memory into bpf_fib_lookup's params arg).
        RegType::PtrToAllocMem { mem_size, .. } => {
            if let Some(sz) = size
                && sz as u64 > mem_size
            {
                env.fail(VerificationError::InvalidArgType { pc, reg });
                error!(
                    "[Verifier] pc {}: alloc-mem {} bytes can't satisfy {}-byte read",
                    pc, mem_size, sz
                );
                return false;
            }
            true
        }
        RegType::PtrToArena { mem_size, .. } => {
            if let Some(sz) = size
                && sz as u64 > mem_size
            {
                env.fail(VerificationError::InvalidArgType { pc, reg });
                error!(
                    "[Verifier] pc {}: arena-mem {} bytes can't satisfy {}-byte read",
                    pc, mem_size, sz
                );
                return false;
            }
            true
        }
        // Kernel `check_mem_access` admits PTR_TO_BTF_ID for ARG_PTR_TO_MEM
        // via PROBE_MEM (verifier.c v6.15 ~L7521): the helper reads bytes
        // from a kernel-struct pointer with fault-tolerant probing
        // (returns zero on page-fault). Permitted in tracing-class
        // contexts where probe_read semantics apply (tp_btf, fentry,
        // fexit, kprobe, raw_tp, lsm, perf_event, iter). Closes
        // task_kfunc_success::test_task_from_pid_invalid where
        // bpf_strncmp(task->comm, ...) hands a `task_struct + 1912`
        // pointer into ARG_PTR_TO_MEM.
        RegType::PtrToBtfId { type_name, flags, .. } => {
            use crate::analysis::machine::reg_types::PtrFlags;
            use crate::ast::ProgramKind;
            let probe_ok = matches!(
                env.ctx.prog_kind,
                ProgramKind::Tracing
                    | ProgramKind::Lsm
                    | ProgramKind::Kprobe
                    | ProgramKind::Tracepoint
                    | ProgramKind::RawTracepoint
                    | ProgramKind::RawTracepointWritable
                    | ProgramKind::PerfEvent
                    | ProgramKind::StructOps
            );
            if !probe_ok {
                env.fail(VerificationError::InvalidArgType { pc, reg });
                error!(
                    "[Verifier] pc {}: PtrToBtfId arg requires tracing-class context for PROBE_MEM",
                    pc
                );
                return false;
            }
            // Mirrors kernel `mem_types` (verifier.c v6.15 L9019): the
            // ARG_PTR_TO_MEM compatibility table accepts only
            // `PTR_TO_BTF_ID | PTR_TRUSTED`, not plain PTR_TO_BTF_ID.
            // `prog_args_trusted()` returns false for fentry / fexit /
            // fmod_ret, so their ctx args are untrusted and rejected
            // here. Closes task_kfunc_failure::task_access_comm4
            // (`bpf_strncmp(task->comm, 16, …)` in fentry).
            if !flags.contains(PtrFlags::TRUSTED) {
                error!(
                    "[Verifier] pc {}: untrusted PtrToBtfId{{{}}} not accepted by ARG_PTR_TO_MEM (kernel mem_types requires PTR_TRUSTED)",
                    pc, type_name
                );
                env.fail(VerificationError::InvalidArgType { pc, reg });
                return false;
            }
            // Bound-check the read against the leaf member size when ALU
            // resolved a containing field. Closes
            // task_kfunc_failure::task_access_comm{1,2} (kernel
            // `btf_struct_access` rejects "access beyond the end of
            // member comm" for `bpf_strncmp(task->comm, 17, …)` and
            // `bpf_strncmp(task->comm + 1, 16, …)`). When the field-ref
            // is absent (no ALU resolved a member, or the entry was
            // cleared) we keep the existing lax accept — this is a
            // tightening, not a replacement.
            if let Some(field) = state.btf_field_refs.get(&reg).cloned()
                && field.struct_name == type_name
                && let Some(sz) = size
            {
                let remaining = field.field_end.saturating_sub(field.current_offset);
                if (sz as u64) > remaining as u64 {
                    error!(
                        "[Verifier] pc {}: read of {} bytes at offset {} exceeds end of member at [{}, {}) in struct {}",
                        pc, sz, field.current_offset, field.field_start, field.field_end, field.struct_name
                    );
                    env.fail(VerificationError::InvalidArgType { pc, reg });
                    return false;
                }
            }
            true
        }
        _ => {
            env.fail(VerificationError::InvalidArgType { pc, reg });
            error!("[Verifier] pc {}: {:?} not a valid memory pointer", pc, reg);
            false
        }
    }
}

/// Validates that a register points to writable memory.
pub(crate) fn validate_writable_mem(
    env: &mut VerifierEnv,
    state: &State,
    _types: &TypeState,
    pc: usize,
    reg: Reg,
    reg_type: RegType,
    size: Option<u32>,
) -> bool {
    match reg_type {
        RegType::PtrToStack { frame_level } => {
            if let Some(off) = state.domain.get_distance_fixed(reg, Reg::R10)
                && let Some(sz) = size
            {
                check_stack_access(
                    env,
                    state,
                    reg,
                    Some(off),
                    0,
                    sz as i64,
                    pc,
                    AccessKind::HelperBuffer,
                    None,
                    frame_level,
                );
            }
            true
        }
        RegType::PtrToMapValue {
            map_idx,
            offset: map_off,
            rdonly,
            ..
        } => {
            if rdonly {
                // Read-only PTR_TO_MAP_KEY (set on cb's R2 by
                // bpf_for_each_map_elem). Helper write buffers can't
                // overwrite the key. Mirrors kernel rejection at the
                // helper-arg level.
                env.fail(VerificationError::MapStoreForbidden { pc, map_idx });
                return false;
            }
            let writable = env
                .ctx
                .map_defs
                .get(map_idx)
                .map(|md| md.map_flags & constants::BPF_F_RDONLY_PROG == 0)
                .unwrap_or(false);
            if !writable {
                env.fail(VerificationError::MapStoreForbidden { pc, map_idx });
                return false;
            }
            // "kptr cannot be accessed indirectly by helper": helper
            // write buffers must not overlap any kptr field. Reuses the
            // same overlap logic as direct stores.
            if let Some(map_def) = env.ctx.map_defs.get(map_idx)
                && let Some(sz) = size
            {
                check_kptr_field_access(
                    env,
                    state,
                    map_def,
                    map_idx,
                    reg,
                    map_off,
                    0,
                    sz as i64,
                    pc,
                    /*is_store=*/ true,
                );
                if env.failed() {
                    return false;
                }
            }
            true
        }
        RegType::PtrToPacket => {
            // Packet pointers are NOT valid for uninit_mem arguments
            // (helper would write to packet, which is not allowed this way)
            env.fail(VerificationError::InvalidArgType { pc, reg });
            error!(
                "[Verifier] pc {}: packet pointer not valid for output buffer",
                pc
            );
            false
        }
        RegType::PtrToPacketMeta => {
            // data_meta region IS writable via helpers/kfuncs (XDP only —
            // kernel's `xdp_metadata_rx_*` kfuncs write hash / rss_type /
            // vlan_tci into the meta region). Bounds-check the write size
            // against the meta-region range via the standard packet-meta
            // access check (mirrors the read path at L1470 added in
            // commit b0ac782).
            if let Some(size) = size {
                crate::analysis::transfer::memory::access::check_load(
                    env, state, reg, size as i64, 0,
                );
                if env.failed() {
                    return false;
                }
            }
            true
        }
        RegType::PtrToAllocMem { mem_size, .. } => {
            // Ringbuf-reserved (or kfunc bpf_obj_new) memory is writable.
            // Bound check: helper write-size must fit within remaining
            // bytes from this pointer's offset (mem_size already encodes
            // the post-offset remaining size after pointer arithmetic
            // through `update_ptr_arithmetic_type`).
            if let Some(sz) = size
                && (sz as u64) > mem_size {
                    env.fail(VerificationError::InvalidArgType { pc, reg });
                    error!(
                        "[Verifier] pc {}: write size {} exceeds remaining alloc-mem size {}",
                        pc, sz, mem_size
                    );
                    return false;
                }
            true
        }
        _ => {
            env.fail(VerificationError::InvalidArgType { pc, reg });
            error!(
                "[Verifier] pc {}: {:?} not a valid writable memory pointer",
                pc, reg
            );
            false
        }
    }
}

// ============================================================================
// Pointer-Size Pair Validation
// ============================================================================

/// Validates all pointer-size pairs declared on a call proto.
/// Returns true if all pairs are valid, false otherwise (error reported).
pub(crate) fn check_mem_size_pairs(
    env: &mut VerifierEnv,
    state: &State,
    proto: &CallProto,
    pc: usize,
) -> bool {
    for pair in proto.mem_size_pairs {
        if !check_single_mem_size_pair(env, proto, state, pair, pc) {
            return false;
        }
    }
    true
}

/// Validates a single pointer-size pair.
pub(crate) fn check_single_mem_size_pair(
    env: &mut VerifierEnv,
    proto: &CallProto,
    state: &State,
    pair: &super::signatures::MemSizePair,
    pc: usize,
) -> bool {
    let ptr_type = state.types.get(pair.ptr_reg);

    // Handle NULL pointer case. NULL-ness is a *type* property (a scalar
    // proven zero passed where a mem-or-null arg is expected), NOT a
    // domain-value property. A concrete non-null pointer type
    // (PtrToMapValue/PtrToStack/...) is never NULL even when its domain
    // bounds read 0 — which is now the norm since map-value pointers
    // track their *offset* (0 for a fresh lookup) in those bounds. Without
    // the `!is_pointer()` guard, a valid map-value ptr at offset 0 is
    // misread as NULL and the helper's "size must be 0 when ptr NULL"
    // rule spuriously rejects the size arg.
    if state.domain.proven_zero(pair.ptr_reg) && !ptr_type.is_pointer() {
        if pair.null_skips_size_check {
            // `__opt` semantics: NULL ptr means no buffer access, any
            // size is fine. Helper returns NULL on the slow path; caller
            // must null-check before deref.
            return true;
        }
        if pair.allow_zero {
            // NULL ptr is OK, but size must also be 0
            if !state.domain.proven_zero(pair.size_reg) {
                env.fail(VerificationError::InvalidArgType {
                    pc,
                    reg: pair.size_reg,
                });
                error!(
                    "[Verifier] pc {}: {:?} must be 0 when {:?} is NULL",
                    pc, pair.size_reg, pair.ptr_reg
                );
                return false;
            }
            return true;
        } else {
            // NULL not allowed for this pair
            env.fail(VerificationError::InvalidArgType {
                pc,
                reg: pair.ptr_reg,
            });
            error!("[Verifier] pc {}: {:?} cannot be NULL", pc, pair.ptr_reg);
            return false;
        }
    }

    // Get size bounds from DBM
    let (_, max_size) = state.domain.get_interval(pair.size_reg);
    if max_size == i64::MAX {
        // Size is unbounded - reject
        env.fail(VerificationError::InvalidArgType {
            pc,
            reg: pair.size_reg,
        });
        error!(
            "[Verifier] pc {}: {:?} has unbounded size",
            pc, pair.size_reg
        );
        return false;
    }

    // Size must be non-negative
    if !state.domain.proven_nonnegative(pair.size_reg) {
        env.fail(VerificationError::InvalidArgType {
            pc,
            reg: pair.size_reg,
        });
        error!(
            "[Verifier] pc {}: {:?} must be non-negative",
            pc, pair.size_reg
        );
        return false;
    }

    // Check zero size
    if max_size == 0 {
        if !pair.allow_zero {
            env.fail(VerificationError::InvalidArgType {
                pc,
                reg: pair.size_reg,
            });
            error!("[Verifier] pc {}: {:?} cannot be 0", pc, pair.size_reg);
            return false;
        }
        // Zero-size accesses are allowed by this helper, but the kernel
        // still validates that the *pointer itself* is within bounds —
        // a variable-offset stack pointer whose range escapes [-512, 0)
        // is rejected even when no byte is actually accessed
        // (`verifier_var_off::zero_sized_access_max_out_of_bound`).
        // Fall through to `check_ptr_access_size` with size=0 only for
        // pointer kinds where range validation makes sense at zero size;
        // unknown / non-memory pointers are not re-checked here.
        if matches!(ptr_type, RegType::PtrToStack { .. }) {
            let ptr_arg_type = proto.args.get(pair.ptr_reg.idx() - 2).unwrap();
            return check_ptr_access_size(
                env,
                state,
                pair.ptr_reg,
                ptr_type,
                *ptr_arg_type,
                0,
                pc,
            );
        }
        return true;
    }

    // Validate pointer can accommodate the access.
    // BCF size-reg stashing (template 4b case iv): pin the size register on
    // env so the map-region refinement callback can read its symbolic
    // expression when building refine_cond. Mirrors BCF's `bcf->size_regno`
    // pattern (kernel set1/0014). Cleared after the access check returns
    // regardless of outcome.
    let ptr_arg_type = proto.args.get(pair.ptr_reg.idx() - 2).unwrap();
    env.bcf_size_reg = Some(pair.size_reg);
    let ok = check_ptr_access_size(
        env,
        state,
        pair.ptr_reg,
        ptr_type,
        *ptr_arg_type,
        max_size as u32,
        pc,
    );
    env.bcf_size_reg = None;
    ok
}

pub(crate) fn checked_by_mem_size_pairs(pairs: &[MemSizePair], reg: Reg) -> bool {
    pairs.iter().any(|pair| pair.ptr_reg == reg)
}

/// Checks that a pointer can safely access `size` bytes.
pub(crate) fn check_ptr_access_size(
    env: &mut VerifierEnv,
    state: &State,
    ptr_reg: Reg,
    ptr_type: RegType,
    ptr_arg_type: ArgKind,
    size: u32,
    pc: usize,
) -> bool {
    match ptr_type {
        RegType::PtrToStack { frame_level } => {
            if let Some(off) = state.domain.get_distance_fixed(ptr_reg, Reg::R10) {
                // Stack: check [off, off + size) is within stack bounds
                // Stack grows down, so valid range is [-512, 0)
                let end_offset = off + size as i64;
                if off < -512 || end_offset > 0 {
                    env.fail(VerificationError::StackOutOfBounds {
                        pc,
                        off,
                        size: size.into(),
                    });
                    error!(
                        "[Verifier] pc {}: stack access [{}, {}) out of bounds",
                        pc, off, end_offset
                    );
                    return false;
                }
                //  / : helper buffer access (read or write) may
                // not overlap an active iter slot or dynptr body. The
                // initialization check below is skipped for PtrToUninitMem
                // (helper writes the bytes), so the opaque-body rule
                // needs its own gate here to catch e.g. probe_read_kernel
                // writing into an iter slot.
                if state
                    .stack_at(frame_level)
                    .access_overlaps_iterator(off, size as i64)
                    || state
                        .stack_at(frame_level)
                        .read_overlaps_dynptr(off, size as i64)
                {
                    env.fail(VerificationError::InvalidStackRead {
                        pc,
                        offset: off,
                    });
                    return false;
                }
                // Also check stack slots are initialized for reads
                if !matches!(
                    ptr_arg_type,
                    ArgKind::PtrToUninitMem | ArgKind::PtrToUninitMemOrNull
                ) {
                    check_stack_arg_readable(
                        env,
                        state,
                        off,
                        size as i64,
                        pc,
                        AccessKind::HelperBuffer,
                    );
                }
                !env.failed()
            } else {
                // Variable offset — use bounds for range check
                let (lo, hi) = state.domain.get_distance_interval(ptr_reg, Reg::R10);
                if lo != i64::MIN && hi != i64::MAX {
                    let end_offset = hi + size as i64;
                    if lo < -512 || end_offset > 0 {
                        env.fail(VerificationError::StackOutOfBounds {
                            pc,
                            off: lo,
                            size: size.into(),
                        });
                        return false;
                    }
                    if !matches!(
                    ptr_arg_type,
                    ArgKind::PtrToUninitMem | ArgKind::PtrToUninitMemOrNull
                ) {
                        for off_candidate in lo..=hi {
                            check_stack_arg_readable(
                                env,
                                state,
                                off_candidate,
                                size as i64,
                                pc,
                                AccessKind::HelperBuffer,
                            );
                            if env.failed() {
                                return false;
                            }
                        }
                    }
                    true
                } else {
                    env.fail(VerificationError::InvalidArgType { pc, reg: ptr_reg });
                    error!(
                        "[Verifier] pc {}: {:?} has unknown stack offset",
                        pc, ptr_reg
                    );
                    false
                }
            }
        }

        RegType::PtrToMapValue {
            map_idx,
            offset,
            id: _,
            ..
        } => {
            // Map value: check offset + size <= value_size
            let Some(map_def) = env.ctx.map_defs.get(map_idx) else {
                env.fail(VerificationError::MapNotFound { pc, map_idx });
                return false;
            };

            // "kptr cannot be accessed indirectly by helper": helper
            // mem-buffer args (the size comes from the paired size arg)
            // must not overlap a kptr field.
            check_kptr_field_access(
                env,
                state,
                map_def,
                map_idx,
                ptr_reg,
                offset,
                0,
                size as i64,
                pc,
                /*is_store=*/ true,
            );
            if env.failed() {
                return false;
            }
            check_map_access(
                env,
                state,
                map_def.value_size as i64,
                offset,
                map_idx,
                ptr_reg,
                map_def,
                0,
                size as i64,
                pc,
            );
            !env.failed()
        }

        RegType::PtrToPacket => {
            // Packet: need to verify against packet bounds (data_end - data)
            check_packet_access(
                env,
                state,
                ptr_reg,
                0,
                size as i64,
                pc,
                AccessKind::HelperBuffer,
            );
            !env.failed()
        }

        // Ring-buffer reservations / arena allocations / dynptr-slice
        // results carry their own bounds in `mem_size`. Kernel accepts
        // these as ARG_PTR_TO_MEM (mirrors `validate_readable_mem`'s
        // PtrToAllocMem arm). Without this, bpf_strncmp(slice_result, ...)
        // — where slice_result has RetKind::PtrToAllocMemFromArg — falls
        // through to the catch-all reject because mem_size_pair validation
        // routes through `check_ptr_access_size`, not `validate_readable_mem`.
        RegType::PtrToAllocMem { mem_size, .. } => {
            if size as u64 > mem_size {
                env.fail(VerificationError::InvalidArgType { pc, reg: ptr_reg });
                error!(
                    "[Verifier] pc {}: alloc-mem {} bytes can't satisfy {}-byte access",
                    pc, mem_size, size
                );
                return false;
            }
            true
        }

        // Kernel admits PTR_TO_BTF_ID for ARG_PTR_TO_MEM via PROBE_MEM
        // (see validate_readable_mem PtrToBtfId arm). Same gating: only
        // tracing-class contexts where probe_read semantics apply.
        // Closes task_kfunc_success::test_task_from_pid_invalid where
        // bpf_strncmp(task->comm, ...) routes through MemSizePair.
        RegType::PtrToBtfId { type_name, flags, .. } => {
            use crate::analysis::machine::reg_types::PtrFlags;
            use crate::ast::ProgramKind;
            let probe_ok = matches!(
                env.ctx.prog_kind,
                ProgramKind::Tracing
                    | ProgramKind::Lsm
                    | ProgramKind::Kprobe
                    | ProgramKind::Tracepoint
                    | ProgramKind::RawTracepoint
                    | ProgramKind::RawTracepointWritable
                    | ProgramKind::PerfEvent
                    | ProgramKind::StructOps
            );
            if !probe_ok {
                env.fail(VerificationError::InvalidArgType { pc, reg: ptr_reg });
                error!(
                    "[Verifier] pc {}: PtrToBtfId arg requires tracing-class context for PROBE_MEM",
                    pc
                );
                return false;
            }
            // Mirrors kernel `mem_types` (verifier.c v6.15 L9019): the
            // ARG_PTR_TO_MEM compatibility table accepts only
            // `PTR_TO_BTF_ID | PTR_TRUSTED`. fentry / fexit / fmod_ret
            // ctx args are untrusted (`prog_args_trusted` returns false)
            // and rejected here even when they reach this site via a
            // mem_size_pair-routed helper. Closes
            // task_kfunc_failure::task_access_comm4.
            if !flags.contains(PtrFlags::TRUSTED) {
                error!(
                    "[Verifier] pc {}: untrusted PtrToBtfId{{{}}} not accepted by ARG_PTR_TO_MEM (kernel mem_types requires PTR_TRUSTED)",
                    pc, type_name
                );
                env.fail(VerificationError::InvalidArgType { pc, reg: ptr_reg });
                return false;
            }
            // Bound-check against the leaf BTF member size when ALU
            // resolved a containing field. Closes
            // task_kfunc_failure::task_access_comm{1,2}: kernel
            // `btf_struct_access` rejects "access beyond the end of
            // member comm" for `bpf_strncmp(task->comm, 17, …)` and
            // `bpf_strncmp(task->comm + 1, 16, …)`. Same logic as the
            // `validate_readable_mem` PtrToBtfId arm — kept in sync
            // because helpers with `mem_size_pairs` route through
            // `check_ptr_access_size`, bypassing `validate_readable_mem`.
            if let Some(field) = state.btf_field_refs.get(&ptr_reg).cloned()
                && field.struct_name == type_name
            {
                let remaining = field.field_end.saturating_sub(field.current_offset);
                if (size as u64) > remaining as u64 {
                    error!(
                        "[Verifier] pc {}: read of {} bytes at offset {} exceeds end of member at [{}, {}) in struct {}",
                        pc, size, field.current_offset, field.field_start, field.field_end, field.struct_name
                    );
                    env.fail(VerificationError::InvalidArgType { pc, reg: ptr_reg });
                    return false;
                }
            }
            true
        }

        _ => {
            env.fail(VerificationError::InvalidArgType { pc, reg: ptr_reg });
            error!(
                "[Verifier] pc {}: {:?} ({:?}) not a valid memory pointer",
                pc, ptr_reg, ptr_type
            );
            false
        }
    }
}

/// Check if a helper ID is valid (within known range).
pub(crate) fn is_valid_helper_id(id: u32) -> bool {
    id <= constants::BPF_HELPER_MAX
}
