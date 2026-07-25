use crate::analysis::machine::error::VerificationError;
// src/analysis/transfer/call/transfer.rs

use super::callback;
use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::{PtrFlags, RegType};
use crate::analysis::machine::state::State;
use crate::analysis::transfer::types::{
    helper_invalidates_packets, update_call_rel_types, update_call_types,
};
use crate::ast::ProgramKind;
use crate::common::constants;
use crate::domains::interval::new_scalar_id;
use crate::domains::numeric::NumericDomain;
use crate::domains::tnum::Tnum;
use log::{debug, error, trace};

use super::checks::validate_helper_args;
use super::mem_checks::{check_mem_size_pairs, is_valid_helper_id};
use super::signatures::get_helper_proto;
use crate::analysis::transfer::alu::helpers::bcf_reg_bounds;

/// Reactive path-unreachable discharge for a helper-argument rejection.
///
/// Mirrors the kernel's CALL dispatch (verifier.c:20761): when
/// `check_helper_call` returns `-EACCES` — which includes
/// `check_func_arg`→`check_reg_type`'s "R%d type=%s expected=<ptr>"
/// reject and the `check_helper_mem_access` size/pointer rejects — the
/// kernel runs `bcf_prove_unreachable`; a matching `kind=UNREACHABLE`
/// bundle entry then discharges the dead path (`bcf_take_discharge` →
/// `return 0`). Companion to the generic-load hook
/// (verifier.c:8259 → `memory::access`). Reactive and solver-gated:
/// `try_emit_path_unreachable_entry` only drops the path on a checkable
/// cvc5 unsat proof of the accumulated `path_cond`, so a genuinely
/// unsafe program is still rejected. Scoped to the arg-validation
/// reject class (`InvalidArgType`, alivio's `check_func_arg` /
/// `check_helper_mem_access` analog).
fn try_discharge_helper_arg_reject(env: &mut VerifierEnv, state: &State, pc: usize) -> bool {
    if matches!(env.error, Some(VerificationError::InvalidArgType { .. }))
        && crate::refinement::emit::try_emit_path_unreachable_entry(env, state)
    {
        log::info!(
            target: "app",
            "[bcf] reactive path-unreachable: discharged helper-arg reject at pc {pc} (cvc5 proof, kind=UNREACHABLE)"
        );
        env.error = None;
        env.bcf_path_unreachable = true;
        true
    } else {
        false
    }
}

/// Transfer function for helper Call instructions.
pub(crate) fn transfer_call(env: &mut VerifierEnv, mut state: State, helper: u32) -> Vec<State> {
    let in_types = state.types.clone();
    let pc = state.pc;

    // =======================================================================
    // Check if helper ID is valid
    // =======================================================================
    if !is_valid_helper_id(helper) {
        env.fail(VerificationError::InvalidHelperId { pc, helper });
        return vec![];
    }

    // ========================================================================
    // Check if the call is forbidden under an active lock
    // ========================================================================
    if state.has_active_lock() && !callback::allowed_while_in_active_lock(helper) {
        env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R0 });
        return vec![];
    }

    // ========================================================================
    // Validate pointer-size pairs
    // ========================================================================
    debug!("[Verifier] pc {}: checking mem size pairs", pc);
    if let Some(p) = get_helper_proto(helper)
        && !check_mem_size_pairs(env, &state, &p, pc)
    {
        try_discharge_helper_arg_reject(env, &state, pc);
        return vec![];
    }

    // ========================================================================
    // Validate helper arguments BEFORE executing
    // ========================================================================
    debug!("[Verifier] pc {}: validating helper arguments", pc);
    validate_helper_args(env, &state, helper, &in_types, pc);
    if env.failed() && try_discharge_helper_arg_reject(env, &state, pc) {
        return vec![];
    }

    // ========================================================================
    // SPECIAL CASES
    // ========================================================================

    // bpf_tail_call
    if helper == constants::BPF_TAIL_CALL {
        if state.has_unreleased_refs() {
            error!("Entering tail calls but has unreleased references!");
            env.fail(VerificationError::UnreleasedReference {});
            return vec![];
        }
        // Kernel rejects bpf_tail_call from any program that takes a
        // refcounted entry arg ("program with __ref argument cannot
        // tail call" — struct_ops_refcounted_fail__tail_call). The
        // ref obligation is on the *program*, not just on the live
        // active_refs at the call site: once the entry-acquired ref
        // is released, the tail-call would jump into a different
        // program that has no record of the ref's prior existence,
        // breaking the kernel's per-prog ref-tracking invariant.
        if let Some(args) = env.ctx.entry_args.as_ref()
            && args.iter().any(|a| {
                matches!(
                    a,
                    crate::analysis::machine::context::EntryArg::TrustedRefcountedTask { .. }
                )
            })
        {
            env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R0 });
            return vec![];
        }
        // Kernel `check_lock` path (verifier.c v6.15 ~L11096) gates
        // tail_call alongside BPF_EXIT under preempt-disable: tail-calling
        // out of a preempt-disabled region would jump into a different
        // program with the disable count leaked.
        if state.in_preempt_disabled() {
            env.fail(VerificationError::TailCallInPreemptDisabled { pc });
            return vec![];
        }
        // Kernel `check_lock` (verifier.c v6.15 ~L11086) also rejects
        // bpf_tail_call inside an irq-disabled region.
        if state.in_irq_disabled() {
            env.fail(VerificationError::IrqState {
                pc,
                reason: "bpf_tail_call inside bpf_local_irq_save-ed region".into(),
            });
            return vec![];
        }
        // Kernel `verifier.c` v6.15 ~L11069: bpf_tail_call cannot be
        // used inside a `bpf_rcu_read_lock`-ed region — the tail-call
        // jumps into a different program with the RCU read lock leaked.
        // Mirrors `tailcall_fail::reject_tail_call_rcu_lock`. Re-uses
        // the existing InvalidArgType / R0 family — no dedicated
        // variant for this rejection family elsewhere.
        //
        // Only reject for *explicit* bpf_rcu_read_lock holds — kernel's
        // `env->cur_state->active_rcu_lock` is incremented by the helper,
        // not by prog-type implicit RCU (kprobe/raw_tp/PerfEvent/etc.,
        // which we model via `implicit_rcu_at_entry`). raw_tp programs
        // legitimately tail_call (test_prog_array_init::entry).
        let implicit_baseline = if state.implicit_rcu_at_entry { 1 } else { 0 };
        if state.rcu_read_depth as i32 > implicit_baseline {
            env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R0 });
            return vec![];
        }
        update_call_types(env, &in_types, &mut state, helper);

        for r in [Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
            state.domain.forget(r);
            state.ptr_const_off.remove(&r);
            state.var_off_contributor.remove(&r);
        }

        // tail-called program may rewrite packet contents, so any packet
        // pointer in callee-saved regs or stack slots is no longer valid
        // afterwards. Mirror kernel `clear_all_pkt_pointers` →
        // `mark_reg_invalid` (verifier.c): privileged loads
        // (`allow_ptr_leaks`, i.e. CAP_BPF) `__mark_reg_unknown` →
        // SCALAR_VALUE (the reg is readable/spillable, just no longer a
        // pointer — a later deref still rejects as "invalid mem access
        // 'scalar'"); only unprivileged loads `__mark_reg_not_init` →
        // NOT_INIT.
        let pkt_invalid_priv = env.ctx.is_privileged();
        let pkt_invalid_ty = || {
            if pkt_invalid_priv {
                RegType::ScalarValue
            } else {
                RegType::NotInit
            }
        };
        for r in Reg::ALL {
            if r == Reg::R10 {
                continue;
            }
            match state.types.get(r) {
                RegType::PtrToPacket | RegType::PtrToPacketEnd | RegType::PtrToPacketMeta => {
                    state.types.set(r, pkt_invalid_ty());
                    state.domain.forget(r);
                }
                _ => {}
            }
        }
        for frame in state.frames.iter_mut() {
            for offset in frame.stack.slot_offsets() {
                let ty = frame.stack.get_slot_type(offset);
                if matches!(
                    ty,
                    RegType::PtrToPacket | RegType::PtrToPacketEnd | RegType::PtrToPacketMeta
                ) {
                    frame.stack.set_slot_type(offset, pkt_invalid_ty(), None);
                }
            }
            // Caller-saved register snapshots (r6-r9) restored on subprog
            // exit must also be invalidated — otherwise main resumes with
            // a stale packet pointer that survived the tail-call. Mirrors
            // kernel `clear_all_pkt_pointers` walking every frame.
            for r in [Reg::R6, Reg::R7, Reg::R8, Reg::R9] {
                if matches!(
                    frame.caller_types.get(r),
                    RegType::PtrToPacket | RegType::PtrToPacketEnd | RegType::PtrToPacketMeta
                ) {
                    frame.caller_types.set(r, pkt_invalid_ty());
                }
            }
        }

        state.pc += 1;
        return vec![state];
    }

    // Special check for sk_release: R1 must have a reference
    if helper == constants::BPF_SK_RELEASE && state.types.get(Reg::R1).get_ref_id().is_none() {
        env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
        return vec![];
    }

    // bpf_sk_release: not allowed in flow_dissector / sockops / tracing
    // / sock-cgroup / lwt-* prog types (kernel's per-prog-type
    // func_proto returns NULL for BPF_FUNC_sk_release in these).
    if helper == constants::BPF_SK_RELEASE
        && matches!(
            env.ctx.prog_kind,
            crate::ast::ProgramKind::FlowDissector
                | crate::ast::ProgramKind::SockOps
                | crate::ast::ProgramKind::Tracing
                | crate::ast::ProgramKind::Tracepoint
                | crate::ast::ProgramKind::RawTracepoint
                | crate::ast::ProgramKind::RawTracepointWritable
                | crate::ast::ProgramKind::Lsm
                | crate::ast::ProgramKind::PerfEvent
                | crate::ast::ProgramKind::Kprobe
        )
    {
        env.fail(VerificationError::HelperNotAllowedForProgram {
            pc,
            helper,
            kind: env.ctx.prog_kind,
        });
        return vec![];
    }

    // bpf_per_cpu_ptr / bpf_this_cpu_ptr: R1 must be a PERCPU-flagged
    // pointer. Kernel `check_helper_call` reports "type=<actual>
    // expected=percpu_ptr_" for anything else (verifier.c v6.15
    // ARG_PTR_TO_PERCPU_BTF_ID dispatch). Accept `PtrToMapKptr*` and
    // `PtrToBtfId*` carrying the PERCPU flag; reject Scalar and other
    // non-percpu pointer types.
    if helper == constants::BPF_THIS_CPU_PTR || helper == constants::BPF_PER_CPU_PTR {
        let r1 = state.types.get(Reg::R1);
        let percpu_ok = matches!(
            r1,
            RegType::PtrToMapKptr { .. }
                | RegType::PtrToMapKptrOrNull { .. }
                | RegType::PtrToBtfId { .. }
                | RegType::PtrToBtfIdOrNull { .. }
        ) && r1
            .ptr_flags()
            .contains(crate::analysis::machine::reg_types::PtrFlags::PERCPU);
        if !percpu_ok {
            env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
            return vec![];
        }
    }

    // bpf_kptr_xchg(&map_value->kptr_field, new_obj):
    //   - R1 must be a `PtrToMapValue` whose constant offset exactly hits
    //     a *referenced* kptr slot (Ref/Rcu/Percpu). Unref slots reject:
    //     kernel "off=N kptr isn't referenced kptr".
    //   - R2 must be either NULL (scalar 0) or a reference-tracked
    //     pointer (`get_ref_id().is_some()`). Kernel "R2 must be referenced".
    //   - Return R0: `PtrToMapKptrOrNull` carrying the slot's
    //     `pointee_btf_id` and matching flags, with a fresh `ref_id` —
    //     this is the *previous* slot contents, ownership transferred to
    //     the program. R2's ref is consumed (transferred into the map).
    if helper == constants::BPF_KPTR_XCHG {
        // Resolve R1 to (kptr_field_kind, pointee_btf_id) — accepts both:
        //   - `PtrToMapValue { offset, map_idx }` aimed at a kptr field in
        //     the map's value BTF (existing path, via `map_def.kptr_fields`).
        //   - `PtrToOwnedKptr { pointee_btf_id, offset }` aimed at a kptr
        //     field embedded inside a `bpf_obj_new`'d struct (new path,
        //     via `extract_value_kptr_fields(pointee_btf_id)`).
        // Kernel `process_kf_arg_ptr_to_kptr` (verifier.c v6.15 ~L13266)
        // accepts both shapes uniformly via `reg_btf_record(reg)`.
        use crate::parsing::elf::{KptrField, KptrFieldKind};
        let r1 = state.types.get(Reg::R1);
        let resolved: Option<(KptrFieldKind, u32)> = match r1 {
            RegType::PtrToMapValue {
                offset: r1_off_opt,
                map_idx,
                ..
            } => {
                let final_off = crate::analysis::transfer::memory::map::resolve_const_map_off(
                    &state,
                    Reg::R1,
                    r1_off_opt,
                    0,
                );
                let Some(off_val) = final_off else {
                    env.fail(VerificationError::KptrAccessVariableOffset { pc, map_idx });
                    return vec![];
                };
                let map_def = match env.ctx.map_defs.get(map_idx) {
                    Some(m) => m,
                    None => {
                        env.fail(VerificationError::MapNotFound { pc, map_idx });
                        return vec![];
                    }
                };
                crate::analysis::transfer::memory::map::kptr_field_at(map_def, off_val, 8)
                    .map(|f| (f.kind, f.pointee_btf_id))
            }
            RegType::PtrToOwnedKptr {
                pointee_btf_id: Some(struct_btf_id),
                offset: r1_off,
                ..
            } => {
                let off_val = r1_off as i64;
                let fields: Vec<KptrField> = env.ctx.btf.extract_value_kptr_fields(struct_btf_id);
                fields
                    .into_iter()
                    .find(|f| f.offset as i64 == off_val)
                    .map(|f| (f.kind, f.pointee_btf_id))
            }
            // Third resolver path: R1 = `xchg_result + K` aimed at a
            // kptr field embedded inside the previously xchg'd object
            // (`unstash_rb_node` idiom). The pointee struct's BTF id
            // identifies the container; `offset` (bumped by ALU) hits
            // the inner kptr field. Mirror the PtrToOwnedKptr arm.
            // Kernel `process_kf_arg_ptr_to_kptr` accepts both shapes
            // uniformly via `reg_btf_record(reg)` (verifier.c v6.15).
            RegType::PtrToMapKptr {
                pointee_btf_id: struct_btf_id,
                offset: r1_off,
                flags,
                ..
            } if flags.contains(crate::analysis::machine::reg_types::PtrFlags::MEM_ALLOC) => {
                let off_val = r1_off as i64;
                let fields: Vec<KptrField> = env.ctx.btf.extract_value_kptr_fields(struct_btf_id);
                fields
                    .into_iter()
                    .find(|f| f.offset as i64 == off_val)
                    .map(|f| (f.kind, f.pointee_btf_id))
            }
            _ => {
                env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
                return vec![];
            }
        };
        let Some((kind, pointee_btf_id)) = resolved else {
            env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
            return vec![];
        };
        if matches!(kind, KptrFieldKind::Unref | KptrFieldKind::Uptr) {
            // Unref kptr: "off=N kptr isn't referenced kptr".
            // Uptr: kptr_xchg has no meaning on a userspace-pointer slot —
            // mirror the unref path's rejection.
            env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
            return vec![];
        }
        let slot_flags = match kind {
            KptrFieldKind::Ref => crate::analysis::machine::reg_types::PtrFlags::MEM_ALLOC,
            KptrFieldKind::Rcu => crate::analysis::machine::reg_types::PtrFlags::RCU,
            KptrFieldKind::Percpu => crate::analysis::machine::reg_types::PtrFlags::PERCPU,
            KptrFieldKind::Unref | KptrFieldKind::Uptr => {
                unreachable!("rejected above")
            }
        };

        // R2: either NULL (scalar 0) or a ref-tracked pointer.
        let r2 = state.types.get(Reg::R2);
        let r2_ref = r2.get_ref_id();
        let r2_is_null = matches!(r2, RegType::ScalarValue) && state.domain.proven_zero(Reg::R2);
        if r2_ref.is_none() && !r2_is_null {
            // "R2 must be referenced"
            env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R2 });
            return vec![];
        }

        // Kernel: PTR_MAYBE_NULL on R2 rejects with "Possibly NULL
        // pointer passed to helper arg2". Programs must null-check
        // a fresh acquire-result before bpf_kptr_xchg consumes it
        // (map_kptr_fail::kptr_xchg_possibly_null). Match any
        // *OrNull pointer-or-null reg-type — the ref_id check above
        // accepts these because the ref-tracking carries through the
        // null branch.
        if matches!(
            r2,
            RegType::PtrToBtfIdOrNull { .. }
                | RegType::PtrToMapKptrOrNull { .. }
                | RegType::PtrToOwnedKptrOrNull { .. }
                | RegType::PtrToSocketOrNull { .. }
                | RegType::PtrToSockCommonOrNull { .. }
                | RegType::PtrToCgroupOrNull { .. }
                | RegType::PtrToTaskOrNull { .. }
                | RegType::PtrToCpumaskOrNull { .. }
        ) {
            env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R2 });
            return vec![];
        }

        // R2 pointee-type compat (kernel `map_kptr_match_type`,
        // verifier.c v6.15 L5780 `btf_struct_ids_match`). For Ref slots
        // the kernel demands a strict struct-name match between R2's
        // pointee BTF and the kptr field's pointee BTF — different
        // BTFs (vmlinux / module / prog) are normalized via the type
        // name. Skip the check when R2 is null (no pointee) or its
        // pointee BTF id is unknown (lite-scope producers).
        if !r2_is_null {
            let kptr_name = env.ctx.btf.struct_name(pointee_btf_id);
            let r2_name = match r2 {
                RegType::PtrToOwnedKptr {
                    pointee_btf_id: Some(id),
                    ..
                } => env.ctx.btf.struct_name(id),
                RegType::PtrToMapKptr { pointee_btf_id, .. } => {
                    env.ctx.btf.struct_name(pointee_btf_id)
                }
                // bpf_percpu_obj_new returns PtrToBtfId carrying the
                // local-BTF type_name directly. Match on that for the
                // pointee-type-mismatch check (kernel
                // "invalid kptr access, R2 type=percpu_ptr_X
                // expected=ptr_Y" — closes
                // percpu_alloc_fail::test_array_map_2).
                RegType::PtrToBtfId { type_name, .. } => Some(type_name),
                _ => None,
            };
            // Skip the pointee-name match when r2's name is "unknown"
            // — that's the sentinel from `intern_btf_type_name_strict`
            // when the local_type_id couldn't resolve to a registered
            // mem_region_model name. Mostly arises with
            // `bpf_percpu_obj_new(struct T)`'s first arg being a load
            // from `const volatile T_btf_ids[idx]`: libbpf relocates
            // those entries to concrete btf_ids at load time, but we
            // read the pre-relocation `.rodata` zero and resolve to
            // "unknown". The strict mismatch check still applies when
            // both sides resolve concretely.
            if let (Some(a), Some(b)) = (kptr_name, r2_name)
                && a != b
                && b != "unknown"
            {
                env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R2 });
                return vec![];
            }
        }

        // Consume R2's ref (transfer ownership into the map). Aliases
        // pointing to the same object are valid for read access only
        // while the surrounding RCU read section holds (the object
        // lives via the map slot, but our local ref is gone). Kernel
        // model: when RCU is held, aliases survive as
        // `PTR_TO_BTF_ID | MEM_RCU` (writable / accepted by per-cpu-
        // ptr); otherwise they must be `mark_reg_unknown`-style
        // invalidated.
        if let Some(id) = r2_ref {
            state.release_ref(id);
            if state.in_rcu_read_section() {
                state.convert_ref_to_non_owning(id);
            } else {
                state.invalidate_ref(id);
            }
        }

        // R0 = previous slot contents: PtrToMapKptrOrNull, fresh ref_id.
        let new_ref = state.acquire_ref();
        state.types.set(
            Reg::R0,
            RegType::PtrToMapKptrOrNull {
                pointee_btf_id,
                ref_id: Some(new_ref),
                flags: slot_flags,
                offset: 0,
            },
        );
        state.domain.forget(Reg::R0);
        state.clear_scalar_id(Reg::R0);

        // Forget caller-saved scalars (R1..R5) per helper-call ABI.
        for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
            state.domain.forget(r);
        }

        // BCF symbolic-state caller-saved clear (β+ Step 0): any pre-call
        // symbolic expression on R0-R5 is stale after a helper call.
        // Subsequent uses must materialize fresh exprs (e.g. via Step 1's
        // map-value anchoring) rather than inherit pre-call values.
        if let Some(bcf) = state.bcf.as_mut() {
            for i in 0..=5 {
                bcf.clear_reg(i);
            }
        }

        state.pc += 1;
        return vec![state];
    }

    // bpf_dynptr_from_mem: R1 (data pointer) must not be a stack pointer.
    // The kernel's "Unsupported reg type fp for bpf_dynptr_from_mem data"
    // — wrapping a stack region as a Local dynptr would let the dynptr
    // outlive its frame. The generic `PtrToMem` validator accepts stack
    // for most helpers, so we special-case here.
    if helper == constants::BPF_DYNPTR_FROM_MEM
        && matches!(state.types.get(Reg::R1), RegType::PtrToStack { .. })
    {
        env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
        return vec![];
    }

    // ========================================================================
    // Proto-flag-driven pre-call mutations
    //
    // bpf_spin_lock / _unlock and bpf_rcu_read_lock / _unlock all run
    // their state mutation here. Arg shape is already validated by
    // `validate_helper_args` (MapValueSpecial { SpinLock } for the lock
    // helpers); this hook only handles the lock/RCU state machine and
    // its rejection cases.
    if let Some(p) = get_helper_proto(helper)
        && !apply_pre_call_lock_flags(env, &mut state, helper, &p)
    {
        return vec![];
    }

    // bpf_sock_map_update: only allowed in BPF_PROG_TYPE_SOCK_OPS programs
    if helper == constants::BPF_SOCK_MAP_UPDATE
        && !matches!(env.ctx.prog_kind, ProgramKind::SockOps)
    {
        env.fail(VerificationError::HelperNotAllowedForProgram {
            pc,
            helper,
            kind: env.ctx.prog_kind,
        });
        return vec![];
    }

    // F: sockmap/sockhash mutation via map_update_elem / map_delete_elem.
    // The two ops have different denylists per the verifier_sockmap_mutate
    // corpus:
    //
    //   update: rejected from RawTracepoint{,Writable} AND SockOps. The
    //     dedicated `bpf_sock_map_update` / `_hash_update` helpers must be
    //     used in those contexts (kernel `may_update_sockmap`,
    //     net/core/sock_map.c v6.15 — covers SOCK_OPS via the
    //     `case BPF_PROG_TYPE_SOCK_OPS: return false;` arm).
    //   delete: rejected from RawTracepoint{,Writable} only — SockOps
    //     accepts (verifier_sockmap_mutate::test_sockops_delete is
    //     __success). The raw_tp rejection comes from the per-prog-type
    //     helper-proto allowlist in `raw_tp_prog_func_proto`, not from
    //     `may_update_sockmap`, but kernel surfaces the same "cannot
    //     update sockmap in this context" message.
    if matches!(
        helper,
        constants::BPF_MAP_UPDATE_ELEM | constants::BPF_MAP_DELETE_ELEM
    ) {
        let map_idx = match state.types.get(Reg::R1) {
            RegType::PtrToMapObject { map_idx } => Some(map_idx),
            _ => None,
        };
        if let Some(idx) = map_idx
            && let Some(map_def) = env.ctx.map_defs.get(idx)
            && matches!(
                map_def.type_,
                constants::BPF_MAP_TYPE_SOCKMAP | constants::BPF_MAP_TYPE_SOCKHASH
            )
        {
            let raw_tp = matches!(
                env.ctx.prog_kind,
                ProgramKind::RawTracepoint | ProgramKind::RawTracepointWritable
            );
            let sockops_update = helper == constants::BPF_MAP_UPDATE_ELEM
                && matches!(env.ctx.prog_kind, ProgramKind::SockOps);
            if raw_tp || sockops_update {
                env.fail(VerificationError::HelperNotAllowedForProgram {
                    pc,
                    helper,
                    kind: env.ctx.prog_kind,
                });
                return vec![];
            }
        }
    }

    // bpf_ktime_get_coarse_ns: not in the helper whitelist for tracing
    // program types (kprobe, tracepoint, perf_event, raw_tracepoint*).
    // Mirrors kernel's per-prog-type helper allowlist.
    if helper == constants::BPF_KTIME_GET_COARSE_NS
        && matches!(
            env.ctx.prog_kind,
            ProgramKind::Kprobe
                | ProgramKind::Tracepoint
                | ProgramKind::PerfEvent
                | ProgramKind::RawTracepoint
                | ProgramKind::RawTracepointWritable
        )
    {
        env.fail(VerificationError::HelperNotAllowedForProgram {
            pc,
            helper,
            kind: env.ctx.prog_kind,
        });
        return vec![];
    }

    // bpf_d_path is restrictive
    if helper == constants::BPF_D_PATH {
        if !matches!(env.ctx.prog_kind, ProgramKind::Tracing | ProgramKind::Lsm) {
            env.fail(VerificationError::HelperNotAllowedForProgram {
                pc,
                helper,
                kind: env.ctx.prog_kind,
            });
            return vec![];
        } else if matches!(env.ctx.prog_kind, ProgramKind::Tracing)
            && (matches!(env.ctx.kfunc.as_deref(), Some("d_path"))
                || matches!(env.ctx.attach_subtype.as_deref(), Some("d_path")))
        {
            env.fail(VerificationError::HelperNotAllowedForProgram {
                pc,
                helper,
                kind: env.ctx.prog_kind,
            });
            return vec![];
        }
    }

    // callback-taking helpers (bpf_loop / bpf_for_each_map_elem /
    // bpf_timer_set_callback) split into two successors:
    //   - "skip": helper returns to pc+1 with its normal return-value
    //     bounds; the callback body is not treated as executing along
    //     this path (abstractly: zero iterations).
    //   - "enter callback": push a callback-flagged frame at the
    //     subprog entry with typed args. On the callback's Exit we
    //     drop the path (see `transfer_exit`), so only the skip path
    //     carries helper post-state forward.
    if callback::is_callback_helper(helper) {
        return callback::transfer_callback_helper(env, state, &in_types, helper);
    }

    // bpf_timer_init cross-arg map_uid check: kernel rejects "timer
    // pointer in R1 map_uid=N doesn't match map pointer in R2
    // map_uid=M" when val (R1's owning map_uid, propagated through
    // chained map-of-maps lookups) and the target map (R2) are
    // different instances. Only fires when both sides have a Some
    // map_uid — direct map decls (PtrToMapObject) carry no uid, so
    // the common timer.c::race pattern (val from same array, R2 is
    // &array) is unaffected. Closes timer_mim_reject::test1.
    if helper == constants::BPF_TIMER_INIT
        && let (
            RegType::PtrToMapValue {
                map_uid: Some(u1), ..
            },
            RegType::PtrToMapValue {
                map_uid: Some(u2), ..
            },
        ) = (in_types.get(Reg::R1), in_types.get(Reg::R2))
        && u1 != u2
    {
        env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R2 });
        return vec![];
    }

    // bpf_get_local_storage doesn't not support type 1 map and flag must be 0
    if helper == constants::BPF_GET_LOCAL_STORAGE {
        if let RegType::PtrToMapObject { map_idx } = state.types.get(Reg::R1)
            && let Some(map_def) = env.ctx.map_defs.get(map_idx)
            && map_def.type_ == constants::BPF_MAP_TYPE_HASH
        {
            env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
            return vec![];
        }
        if !state.domain.proven_zero(Reg::R2) {
            env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R2 });
            return vec![];
        }
    }

    // ========================================================================
    // Normal helper handling
    // ========================================================================

    // BCF symbolic R0 clear (β+ Step 0). MUST run before
    // update_call_types: clearing later would override the anchor bindings
    // update_call_types sets for direct-PtrToMapValue returns (array-map
    // lookup with const key, bpf_get_local_storage). Clearing here, before
    // the type update, lets those anchor calls be the final word.
    if let Some(bcf) = state.bcf.as_mut() {
        bcf.clear_reg(0);
    }

    // 1. Update types
    update_call_types(env, &in_types, &mut state, helper);

    // 2. Apply return value bounds for specific helpers
    apply_return_bounds(&mut state, helper);

    // 2.1 Scalar ID for helper return value.
    // An unknown scalar R0 gets a fresh id so that copies of it can later
    // be linked and refined together. Pointer or constant returns
    // don't need scalar linking.
    use crate::analysis::machine::reg_types::RegType;
    if state.types.get(Reg::R0) == RegType::ScalarValue && state.get_tnum(Reg::R0).is_unknown() {
        state.alloc_scalar_id(Reg::R0);
    } else {
        state.clear_scalar_id(Reg::R0);
    }

    // 2.5 Initialize memory buffers for PtrToUninitMem arguments
    initialize_uninit_mem_args(&mut state, &in_types, helper);

    // 3. Update DBM - forget caller-saved registers and reset Tnums.
    // UNCONDITIONAL (see update_call_types): the kernel scratches r0-r5
    // at every helper call regardless of bpf_fastcall; value preservation
    // belongs to the spill/fill pattern, which is verified as-written.
    {
        for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
            state.domain.forget(r);
            state.set_tnum(r, Tnum::unknown());
            state.clear_scalar_id(r);
        }
        // Kernel check_helper_call resets ALL caller-saved regs r0-r5 via
        // mark_reg_not_init (verifier.c:12370-12373) — the whole
        // bpf_reg_state, including ptr_reg->off; R0's return type is then
        // re-marked with off=0 (mark_reg_known_zero). The ptr_const_off /
        // var_off_contributor side-maps must be cleared to match.
        for r in [Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
            state.ptr_const_off.remove(&r);
            state.var_off_contributor.remove(&r);
        }
        // BCF symbolic-state caller-saved clear (β+ Step 0): mirror the
        // domain/tnum/id clears above.
        if let Some(bcf) = state.bcf.as_mut() {
            for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
                if let Some(i) = r.bcf_idx() {
                    bcf.clear_reg(i);
                }
            }
        }
    }

    // 4. Forget packet pointer DBM entries if they were invalidated
    if helper_invalidates_packets(helper) {
        for r in Reg::ALL {
            if r != Reg::R10 {
                match in_types.get(r) {
                    RegType::PtrToPacket | RegType::PtrToPacketEnd | RegType::PtrToPacketMeta => {
                        state.domain.forget(r);
                    }
                    _ => {}
                }
            }
        }
        state.domain.reset_packet_anchors();
    }

    // 5. Advance PC and return
    state.pc += 1;
    vec![state]
}

/// Initializes stack slots that were passed as PtrToUninitMem helper arguments.
fn initialize_uninit_mem_args(
    state: &mut State,
    in_types: &crate::analysis::machine::reg_types::TypeState,
    helper: u32,
) {
    use super::signatures::ArgKind;
    use crate::analysis::transfer::types::update_store_types;
    use crate::ast::MemSize;

    if let Some(sig) = get_helper_proto(helper) {
        for pair in sig.mem_size_pairs {
            if let Some(ptr_arg_type) = sig.args.get(pair.ptr_reg.idx().saturating_sub(2))
                && matches!(
                    ptr_arg_type,
                    ArgKind::PtrToUninitMem | ArgKind::PtrToUninitMemOrNull
                )
            {
                if let RegType::PtrToStack { frame_level } = in_types.get(pair.ptr_reg) {
                    if let Some(off) = state.domain.get_distance_fixed(pair.ptr_reg, Reg::R10) {
                        let (_, max_size) = state.domain.get_interval(pair.size_reg);
                        {
                            if max_size != i64::MAX && max_size > 0 {
                                let max_bytes = (max_size as usize).min(512); // Bound to max stack size just in case
                                let stack = state.stack_at_mut(frame_level);
                                // Kernel check_stack_range_initialized clobber
                                // (verifier.c:8635-8640): a helper WRITE into a
                                // slot holding a spilled reg does
                                // __mark_reg_unknown(spilled_ptr) + scrub_spilled_slot
                                // on EVERY byte of that slot — not just the written
                                // bytes.
                                if let Ok(off16) = i16::try_from(off) {
                                    stack.scrub_spilled_slots_for_write(off16, max_bytes);
                                }
                                for i in 0..max_bytes {
                                    if let Ok(slot) = i16::try_from(off + i as i64) {
                                        update_store_types(
                                            stack,
                                            RegType::ScalarValue,
                                            MemSize::U8,
                                            Some(slot as i64),
                                        );
                                        // Destroy the spilled VALUE, not just
                                        // the type. The kernel's
                                        // check_helper_call marks an
                                        // ARG_PTR_TO_UNINIT_MEM output buffer
                                        // STACK_MISC + __mark_reg_unknown
                                        // (verifier.c:8606 / :12094 byte-wise
                                        // BPF_WRITE). Without this, a constant
                                        // the caller spilled into the buffer
                                        // before the call would survive in the
                                        // slot model — reading a helper's
                                        // uninitialized output as a known
                                        // value is a soundness hole.
                                        stack.invalidate_slot(slot);
                                    }
                                }
                            }
                        }
                    } else {
                        trace!("Could not get fixed distance to R10");
                    }
                } else {
                    trace!(
                        "Arg is NOT PtrToStack, it is {:?}",
                        state.types.get(pair.ptr_reg)
                    );
                }
            }
        }
    }
}

/// Apply return value bounds based on helper semantics.
/// Public re-export of `apply_return_bounds` for the cb-Exit
/// propagation path in `transfer/mod.rs`. The cb-Exit path needs the
/// same R0 bounds the helper would normally produce on its skip-path,
/// minus the side-effect modeling that depends on caller-side
/// `in_types`. `apply_return_bounds` is pure on-state.
pub(crate) fn apply_return_bounds_for_cb_helper(state: &mut State, helper: u32) {
    apply_return_bounds(state, helper);
}

/// Narrow R0 to a documented mixed-sign helper-return range
/// `[lo, hi]` where `lo < 0 ≤ hi`. Mirrors the kernel's
/// `do_refine_retval_range` shape: set s32/s64 bounds via signed
/// constraints, then ensure the unsigned view stays at full range
/// (mixed-sign → two disjoint unsigned pieces, kernel-faithful
/// answer is `[0, u64::MAX]`).
///
/// Without the unsigned restore, `assume_le_imm(R0, hi)` (which
/// calls `assume_sle`) would cross-propagate `umax = min(umax, hi)`,
/// corrupting the unsigned view; `sync_bounds` path-1 then
/// propagates the wrong umax back to `s32_min = 0` (instead of
/// `lo`). Downstream `bound_reg32` emits `JLE(v, hi)` instead of
/// `JSLE(v, hi)` and skips the matching `JSGE(v, lo)` — silently
/// changing the canonical hash so the kernel's BCF refine_cond
/// lookup misses.
fn apply_mixed_sign_ret_bounds(state: &mut State, lo: i64, hi: i64) {
    debug_assert!(
        lo < 0 && hi >= 0,
        "apply_mixed_sign_ret_bounds requires lo<0<=hi; got lo={lo} hi={hi}"
    );
    if hi != i64::MAX {
        state.domain.assume_le_imm(Reg::R0, hi);
    }
    state.domain.assume_ge_imm(Reg::R0, lo);
    // After both narrowings, R0 should be mixed-sign. The
    // `assume_le_imm` step likely corrupted umax (it cross-
    // propagated to umax=hi because hi>=0). Restore the unsigned
    // view to full range, then re-derive 32-bit halves via
    // sync_bounds so the signed s32 view ends up matching the
    // (now-correct) 64-bit signed interval.
    let (smin, _) = state.domain.get_interval(Reg::R0);
    if smin < 0 {
        state.domain.restore_full_unsigned_range(Reg::R0);
    }
}

pub(super) fn apply_return_bounds(state: &mut State, helper: u32) {
    // `update_call_types` (run just before this) sets up domain offset
    // tracking for map-value-returning helpers via `init_map_value_ptr`
    // (R0.bounds = offset [0,0], R0.ptr_offset = Some). An unconditional
    // `forget(R0)` here wipes that, so the offset never reaches the reg
    // it is copied into (`r6 = r0`), and the map-region refinement reads
    // min_off = i64::MIN -> "Unbounded variable map access". Preserve
    // the offset tracking for map-value R0; the generic scalar-return
    // reset still applies to every other helper.
    let r0_is_map_value_ptr = matches!(
        state.types.get(Reg::R0),
        RegType::PtrToMapValue { .. } | RegType::PtrToMapValueOrNull { .. }
    );
    if !r0_is_map_value_ptr {
        state.domain.forget(Reg::R0);
        state.set_tnum(Reg::R0, Tnum::unknown());
    }
    // Pre-materialize R0's BCF cache with **kernel-view** bounds
    // (unbounded scalar) — ONLY when alivio's domain would narrow R0
    // tighter than the kernel's `do_refine_retval_range`. The kernel's
    // helper proto dictates which helpers narrow R0; for helpers
    // whose proto returns an unbounded scalar (e.g.
    // `bpf_get_prandom_u32` / `bpf_get_smp_processor_id`), the kernel's
    // `bcf_reg_expr` caches R0 as `VAR_64`. alivio's `apply_return_bounds`
    // below tightens R0 to `[0, u32::MAX]` for those (alivio-only
    // precision), which would otherwise drive `materialize_reg` into
    // the `fit_u32` branch and cache R0 as `ZEXT(VAR_32)` — diverging
    // from the kernel's runtime CONJ. Pre-caching with unknown bounds
    // forces VAR_64 to match.
    //
    // For helpers where the kernel ALSO narrows (the `do_refine_retval_range`
    // set — error-return helpers, `bpf_probe_read_str` family, etc.),
    // alivio and the kernel agree on bounds. Skipping the pre-cache here
    // lets `materialize_reg` fire lazily with the narrowed bounds, which
    // matches the kernel's `bcf_reg_expr` choice of SEXT(VAR_32) +
    // `bcf_bound_reg` preds at the first symbolic use.
    let alivio_narrower_than_kernel = matches!(
        helper,
        constants::BPF_GET_PRANDOM_U32
            | constants::BPF_GET_CGROUP_CLASS_ID
            | constants::BPF_GET_HASH_RECALC
            // "0 on success / -errno" group below: alivio narrows R0 to
            // [-MAX_ERRNO, 0], but the kernel's `do_refine_retval_range`
            // (verifier.c) refines ONLY get_stack / get_task_stack /
            // probe_read{,_kernel,_user}_str / get_smp_processor_id —
            // every other RET_INTEGER helper (incl. these) stays a
            // fully-unbounded scalar (`mark_reg_unknown`). So alivio must
            // pre-cache R0's bcf_expr as the kernel-shape unbounded
            // VAR_64; otherwise materialize_reg takes the fit_s32 path
            // (32-bit var + spurious bcf_bound_reg32 preds), diverging
            // from the kernel CONJ.
            // The abstract-domain bound below is kept (alivio-only
            // verification precision); only the BCF goal is made faithful.
            | constants::BPF_MAP_UPDATE_ELEM
            | constants::BPF_MAP_DELETE_ELEM
            | constants::BPF_SKB_STORE_BYTES
            // BPF_SKB_LOAD_BYTES intentionally NOT pre-cached: pre-caching
            // R0 as an unbounded VAR_64 here freezes its BCF expr before
            // a subsequent `w0 == 0` branch narrows R0's low-32 to 0, so
            // the kernel's post-narrow bounds would never reach the goal.
            // Letting it materialize lazily is faithful: at the narrowed
            // point R0 = [low-32=0, high unknown] fails fit_u32/fit_s32
            // (high 32 unknown) so it still takes the VAR_64 path — now
            // WITH bound_reg64 preds.
            | constants::BPF_XDP_ADJUST_HEAD
            | constants::BPF_L3_CSUM_REPLACE
            | constants::BPF_L4_CSUM_REPLACE
            | constants::BPF_GET_CURRENT_COMM
            | constants::BPF_SKB_VLAN_PUSH
            | constants::BPF_SKB_VLAN_POP
            | constants::BPF_SOCK_MAP_UPDATE
            // CSUM_DIFF: alivio narrows R0 to [-MAX_ERRNO, 0xffffffff]
            // (apply_return_bounds below) but the kernel's
            // do_refine_retval_range does NOT — its R0 stays a fully
            // unbounded scalar, so bcf_reg_expr at the first read emits a
            // bare VAR_64 with NO bound preds. Without the pre-cache,
            // alivio's first read would emit an orphaned bound pair.
            | constants::BPF_CSUM_DIFF
    );
    if alivio_narrower_than_kernel
        && let Some(bcf) = state.bcf.as_mut()
        && let Some(d) = Reg::R0.bcf_idx()
    {
        let _ = bcf.reg_expr(d, &crate::refinement::symbolic::RegBounds::unknown(), false);
    }
    // NOTE: the BCF R0 bcf_expr clear lives at the top of
    // `transfer_call` (before `update_call_types`) so it doesn't override
    // anchors set during type assignment. See the matching comment there.
    match helper {
        constants::BPF_REDIRECT => {
            state.domain.assume_ge_imm(Reg::R0, 0);
            state.domain.assume_le_imm(Reg::R0, 7);
        }
        constants::BPF_FIB_LOOKUP => {
            state.domain.assume_ge_imm(Reg::R0, 0);
            state.domain.assume_le_imm(Reg::R0, 8);
        }
        constants::BPF_MAP_UPDATE_ELEM
        | constants::BPF_MAP_DELETE_ELEM
        | constants::BPF_SKB_STORE_BYTES
        | constants::BPF_SKB_LOAD_BYTES
        | constants::BPF_XDP_ADJUST_HEAD
        | constants::BPF_L3_CSUM_REPLACE
        | constants::BPF_L4_CSUM_REPLACE
        | constants::BPF_GET_CURRENT_COMM
        | constants::BPF_SKB_VLAN_PUSH
        | constants::BPF_SKB_VLAN_POP
        | constants::BPF_SOCK_MAP_UPDATE => {
            // Kernel `do_refine_retval_range` (verifier.c:11733) does NOT
            // narrow R0 for these helpers — only for get_stack family +
            // get_smp_processor_id.
            // (NO-OP: bounds left at helper-return default — fully
            // unbounded scalar, matching kernel.)
        }
        constants::BPF_GET_PRANDOM_U32
        | constants::BPF_GET_CGROUP_CLASS_ID
        | constants::BPF_GET_HASH_RECALC => {
            // Returns a positive u32
            state.domain.assume_ge_imm(Reg::R0, 0);
            state.domain.assume_le_imm(Reg::R0, 0xFFFF_FFFF);
            state.set_tnum(Reg::R0, Tnum::u32_unknown());
            // Assign scalar_id for tracking related scalars
            interval_set_scalar_id(&mut state.domain, Reg::R0);
        }
        constants::BPF_CSUM_DIFF => {
            // Returns a positive u32 (checksum) or negative error.
            // Mixed-sign [-MAX_ERRNO, 0xFFFF_FFFF].
            apply_mixed_sign_ret_bounds(state, -constants::MAX_ERRNO, 0xFFFF_FFFF);
            state.set_tnum(Reg::R0, Tnum::u32_unknown());
        }
        constants::BPF_GET_TASK_STACK => {
            let pairs = get_helper_proto(helper)
                .map(|p| p.mem_size_pairs)
                .unwrap_or(&[]);
            let size_reg = pairs[0].size_reg;
            let (_, hi) = state.domain.get_interval(size_reg);
            state.domain.assume_le_imm(Reg::R0, hi);
        }
        constants::BPF_GET_STACK => {
            // Mixed-sign [-MAX_ERRNO, size_max].
            let pairs = get_helper_proto(helper)
                .map(|p| p.mem_size_pairs)
                .unwrap_or(&[]);
            let size_reg = pairs[0].size_reg;
            let (_, hi) = state.domain.get_interval(size_reg);
            apply_mixed_sign_ret_bounds(state, -constants::MAX_ERRNO, hi);
        }
        constants::BPF_GET_BRANCH_SNAPSHOT => {
            // R0 = bytes written into the buffer (success) or -errno.
            // Bound by the size arg (R2). Mixed-sign.
            let pairs = get_helper_proto(helper)
                .map(|p| p.mem_size_pairs)
                .unwrap_or(&[]);
            let hi = pairs
                .first()
                .map(|p| state.domain.get_interval(p.size_reg).1)
                .unwrap_or(i64::MAX);
            apply_mixed_sign_ret_bounds(state, -constants::MAX_ERRNO, hi);
        }
        // Mirrors kernel's `do_refine_retval_range()` for the str-family
        // probe-read helpers: R0 is bounded by [-MAX_ERRNO, R2_max].
        // Without this refinement, `if (len >= 0) ptr += len;` (a common
        // varlen idiom) rejects as `Add ptr, unbounded-scalar` at the
        // pointer-arithmetic check. Bound R0 by R2 directly (the size
        // arg) rather than via the proto's mem_size_pairs, so this fires
        // for helpers without a registered proto (PROBE_READ_KERNEL_STR /
        // PROBE_READ_USER_STR are intentionally unmodeled at the proto
        // level — adding them surfaces a stale-zone-offset issue in
        // mem_size_pair validation that would regress unrelated tests).
        constants::BPF_PROBE_READ_STR
        | constants::BPF_PROBE_READ_USER_STR
        | constants::BPF_PROBE_READ_KERNEL_STR => {
            // Mixed-sign [-MAX_ERRNO, R2_max].
            let (_, hi) = state.domain.get_interval(Reg::R2);
            apply_mixed_sign_ret_bounds(state, -constants::MAX_ERRNO, hi);
        }
        constants::BPF_KFUNC_CALL_DUMMY => {
            // Assume unsupported external kfuncs return an unknown opaque pointer that can be dereferenced
            state.types.set(
                Reg::R0,
                RegType::PtrToBtfId {
                    type_name: "unknown",
                    flags: PtrFlags::UNTRUSTED,
                    ref_id: None,
                },
            );
        }
        _ => {}
    }

    // Eagerly materialize R0's BCF symbolic expression for helpers whose
    // kernel-side `do_refine_retval_range` narrows R0 to `[-MAX_ERRNO,
    // size_max]`. Without this, R0's symbolic var + bound preds only get
    // emitted on R0's first symbolic use — but the next helper call may
    // overwrite R0 first (via `clear_reg(0)` at transfer_call entry),
    // dropping the bounds from the path_cond entirely. The kernel's
    // `bcf_track` suffix walk catches this via `check_reg_arg`'s eager
    // `bcf_reg_expr` call (verifier.c:4086) — every reg read materializes.
    // We mirror at the helper-return narrow point: each call's fresh R0 gets
    // its own SEXT(VAR_32) + 2 bound preds, even if R0 is overwritten before
    // a symbolic use.
    let kernel_narrows_r0_via_do_refine = matches!(
        helper,
        constants::BPF_GET_STACK
            | constants::BPF_GET_TASK_STACK
            | constants::BPF_PROBE_READ_STR
            | constants::BPF_PROBE_READ_USER_STR
            | constants::BPF_PROBE_READ_KERNEL_STR
    );
    if kernel_narrows_r0_via_do_refine {
        let bounds = bcf_reg_bounds(state, Reg::R0);
        if let Some(bcf) = state.bcf.as_mut()
            && let Some(d) = Reg::R0.bcf_idx()
        {
            let _ = bcf.reg_expr(d, &bounds, false);
        }
    }
}

/// Transfer function for relative Call (BPF-to-BPF function call) instructions.
pub(crate) fn transfer_call_rel(
    env: &mut VerifierEnv,
    mut state: State,
    target: usize,
) -> Vec<State> {
    // Kernel `bpf_reset_live_stack_callchain` at frame push: the open
    // per-insn write bracket belongs to the caller's callchain; a
    // CallRel must not commit must_write at the callsite (the callsite's
    // must_write comes from `propagate_to_outer_instance` at callee
    // exit).
    crate::analysis::flow::live_stack::invalidate_write_bracket(env);

    let pc = state.pc;
    // Kernel: `state->curframe + 1 >= MAX_CALL_FRAMES (8)` rejects when
    // the *new* frame's index would reach the limit. Our 1-based
    // `num_frames()` counts the current depth. The kernel allows 8
    // frames total (main + 7 subprog frames); a chain like
    // `test_global_func4`'s `main → f7 → ... → f1` hits exactly 8
    // frames at f1. Use `> 8` so we reject only on the *9th* push.
    if state.num_frames() > 8 {
        env.fail(VerificationError::MaxCallDepthExceeded { pc });
        return vec![];
    }

    // Reject any direct (or transitively-resolved) call whose target
    // resolves to the registered exception callback. The kernel
    // disallows the program from invoking its own exception_cb directly:
    // unwinding is the only legal entry into it. Mirrors the kernel's
    // "cannot call exception cb directly" diagnostic.
    if let Some(cb_name) = env.ctx.exception_callback.as_deref()
        && let Some(target_name) = env.ctx.pc_to_subprog_name.get(&target)
        && target_name == cb_name
    {
        env.fail(VerificationError::ExceptionCallbackInvalid {
            reason: "cannot call exception cb directly".to_string(),
        });
        return vec![];
    }

    // global subprogs are verified independently against their
    // declared BTF FUNC_PROTO. At each call site we must:
    //   1. Reject malformed global signatures (void return, FWD args)
    //      that the kernel would reject at function-load time.
    //   2. Validate caller's R1..R5 against declared types (catches
    //      "Caller passes invalid args into func#N").
    //   3. After push_frame, override callee's R1..R5 with declared
    //      types so the body is verified the way the kernel would —
    //      pointers come in as PTR_TO_MEM | PTR_MAYBE_NULL, etc.
    // Static subprogs skip all of this: callee inherits caller's
    // concrete types, matching kernel `__noinline static` semantics.
    let callee_global = env
        .ctx
        .pc_to_subprog_name
        .get(&target)
        .cloned()
        .filter(|n| env.ctx.btf.is_global_func(n));
    if let Some(name) = callee_global.as_ref() {
        // Kernel verifier.c L10538: global subprog calls are unconditionally
        // rejected while a bpf_spin_lock is held. Global subprogs are
        // verified separately and may execute helpers/kfuncs that are
        // disallowed under lock; static subprogs are inlined and exempt.
        if state.has_active_lock() {
            env.fail(VerificationError::GlobalFuncCallUnderLock {
                pc,
                func: name.clone(),
            });
            return vec![];
        }
        // Static call-graph gate: kernel rejects a global subprog whose
        // body transitively reaches a MIGHT_SLEEP helper/kfunc when the
        // call site is inside an irq-, preempt-, or RCU-disabled region
        // (verifier.c v6.15 ~L10543). Path-independent: catches sleepable
        // calls that escape the per-call MIGHT_SLEEP gate when the
        // dataflow-pruned path dead-codes the inner sleepable call.
        let explicit_rcu_baseline = if state.implicit_rcu_at_entry { 1 } else { 0 };
        let rcu_active = state.rcu_read_depth > explicit_rcu_baseline;
        if env.ctx.may_sleep_subprogs.contains(&target)
            && (state.in_irq_disabled() || state.in_preempt_disabled() || rcu_active)
        {
            env.fail(VerificationError::GlobalFuncMaySleepInNonSleepable {
                pc,
                func: name.clone(),
            });
            return vec![];
        }
        if env.ctx.btf.func_returns_void(name) {
            env.fail(VerificationError::GlobalFuncMalformed {
                pc,
                func: name.clone(),
                reason: "doesn't return scalar".to_string(),
            });
            return vec![];
        }
        if let Some(args) = env.ctx.btf.resolve_global_func_args(name) {
            // Reject malformed args (FWD).
            for (i, arg) in args.iter().enumerate() {
                if let crate::parsing::btf::GlobalFuncArg::PtrToFwd { name: tname } = arg {
                    env.fail(VerificationError::GlobalFuncMalformed {
                        pc,
                        func: name.clone(),
                        reason: format!(
                            "reference type('FWD {}') size cannot be determined (arg #{})",
                            tname,
                            i + 1
                        ),
                    });
                    return vec![];
                }
            }
            // Caller-side type compatibility check.
            let arg_regs = [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5];
            for (i, (arg, reg)) in args.iter().zip(arg_regs.iter()).enumerate() {
                let actual = state.types.get(*reg);
                // For scalars passed where a pointer is declared, the
                // kernel admits only literal NULL — not arbitrary
                // scalar values. Use the domain to prove the value is
                // exactly 0; otherwise reject.
                let scalar_is_zero = || {
                    let (lo, hi) = state.domain.get_interval(*reg);
                    lo == 0 && hi == 0
                };
                if !caller_arg_compatible(arg, actual, scalar_is_zero) {
                    env.fail(VerificationError::GlobalFuncBadCallerArg {
                        pc,
                        func: name.clone(),
                        arg_index: i,
                    });
                    return vec![];
                }
                // For PtrToStack passed to PtrToMem(mem_size), the
                // kernel additionally verifies the caller's stack
                // region is large enough and fully initialized. This
                // catches "small struct passed to large declared arg"
                // — the kernel emits "invalid read from stack" when
                // the callee would later access bytes past the
                // caller's allocation.
                if let crate::parsing::btf::GlobalFuncArg::PtrToMem { mem_size, .. } = arg
                    && let RegType::PtrToStack { .. } = actual
                    && let Some(off) = state.domain.get_distance_fixed(*reg, Reg::R10)
                {
                    crate::analysis::transfer::memory::check_stack_arg_readable(
                        env,
                        &state,
                        off,
                        *mem_size as i64,
                        pc,
                        crate::analysis::transfer::memory::access::AccessKind::HelperBuffer,
                    );
                    if env.failed() {
                        return vec![];
                    }
                }
                // Read-only map value (.rodata) passed to a writable
                // PtrToMem arg: the global subprog signature has no
                // `__arg_const` tag, so the callee may store through it.
                // Kernel reports "Caller passes invalid args into func#N".
                if let crate::parsing::btf::GlobalFuncArg::PtrToMem { .. } = arg
                    && let RegType::PtrToMapValue { map_idx, .. } = actual
                    && let Some(map_def) = env.ctx.map_defs.get(map_idx)
                    && map_def.map_flags & crate::common::constants::BPF_F_RDONLY_PROG != 0
                {
                    env.fail(VerificationError::GlobalFuncBadCallerArg {
                        pc,
                        func: name.clone(),
                        arg_index: i,
                    });
                    return vec![];
                }
                // "kptr cannot be accessed indirectly by helper" extends
                // to global subprog calls: a `PtrToMapValue` arg whose
                // declared mem region overlaps a kptr field is rejected.
                if let crate::parsing::btf::GlobalFuncArg::PtrToMem { mem_size, .. } = arg
                    && let RegType::PtrToMapValue {
                        offset: map_off,
                        map_idx,
                        ..
                    } = actual
                    && let Some(map_def) = env.ctx.map_defs.get(map_idx)
                {
                    crate::analysis::transfer::memory::check_kptr_field_access(
                        env,
                        &state,
                        map_def,
                        map_idx,
                        *reg,
                        map_off,
                        0,
                        *mem_size as i64,
                        pc,
                        /*is_store=*/ true,
                    );
                    if env.failed() {
                        return vec![];
                    }
                }
            }
        }
    }

    // Global-subprog calls get an isolated frame: kernel verifies them
    // separately, so RCU lock-state changes inside the body must NOT
    // propagate back to the caller. `push_global_subprog_frame` stamps
    // a snapshot of `rcu_read_depth` that `transfer_exit` restores on
    // Exit. Static (non-global) subprogs use the regular `push_frame`
    // since the kernel walks them inline (state changes propagate).
    if callee_global.is_some() {
        state.push_global_subprog_frame(pc + 1);
    } else {
        state.push_frame(pc + 1);
    }
    update_call_rel_types(&mut state);

    // Override callee R1..R5 with declared types for global subprogs.
    // Pointer args become PtrToAllocMemOrNull bounded by the pointee's
    // BTF size — the callee must null-check before dereferencing,
    // which is the surface for `invalid mem access 'mem_or_null'`
    // when the body unconditionally derefs.
    if let Some(name) = callee_global.as_ref()
        && let Some(args) = env.ctx.btf.resolve_global_func_args(name)
    {
        let arg_regs = [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5];
        for (arg, reg) in args.iter().zip(arg_regs.iter()) {
            match arg {
                crate::parsing::btf::GlobalFuncArg::Scalar => {
                    state.types.set(*reg, RegType::ScalarValue);
                    state.domain.forget(*reg);
                }
                crate::parsing::btf::GlobalFuncArg::PtrToMem { mem_size, nonnull } => {
                    let id = crate::analysis::machine::reg_types::new_ptr_id();
                    let ty = if *nonnull {
                        RegType::PtrToAllocMem {
                            id,
                            mem_size: *mem_size as u64,
                            ref_id: None,
                            dynptr_id: None,
                            rdonly: false,
                        }
                    } else {
                        RegType::PtrToAllocMemOrNull {
                            id,
                            mem_size: *mem_size as u64,
                            ref_id: None,
                            dynptr_id: None,
                            rdonly: false,
                        }
                    };
                    state.types.set(*reg, ty);
                    state.domain.forget(*reg);
                }
                crate::parsing::btf::GlobalFuncArg::PtrToCtx => {
                    state.types.set(*reg, RegType::PtrToCtx);
                    state.domain.forget(*reg);
                }
                crate::parsing::btf::GlobalFuncArg::PermissivePtr => {
                    // Most `void *` global subprog args are ctx
                    // pointers in practice; pick PtrToCtx as the
                    // best guess for callee body verification.
                    state.types.set(*reg, RegType::PtrToCtx);
                    state.domain.forget(*reg);
                }
                crate::parsing::btf::GlobalFuncArg::PtrToFwd { .. } => {
                    // Already rejected above; keep arm exhaustive.
                }
                crate::parsing::btf::GlobalFuncArg::PtrToDynptr => {
                    // Preserve caller's stack pointer + dynptr-slot
                    // state so the callee's `bpf_dynptr_data` / `_slice`
                    // calls can resolve the slot. Kernel
                    // ARG_PTR_TO_DYNPTR | MEM_RDONLY (btf.c:7784) — no
                    // override.
                }
                crate::parsing::btf::GlobalFuncArg::PtrToArena => {
                    // Preserve caller's PtrToArena. Arena is a sparse
                    // 4GB address space and the body verifies arithmetic
                    // on it via the PtrToArena fast-path in
                    // check_ptr_arithmetic — no override needed.
                }
                crate::parsing::btf::GlobalFuncArg::PtrToBtfIdTrusted {
                    type_name,
                    nullable,
                } => {
                    use crate::analysis::machine::reg_types::PtrFlags;
                    // type_name is a runtime string; the RegType variant
                    // holds a `&'static str`, so leak the (small, bounded)
                    // name once. Subsequent calls reuse the leaked copy
                    // via the leak-safe identity check on the call site
                    // path — bounded by the number of distinct kernel
                    // types referenced as `__arg_trusted` in any one
                    // verified ELF.
                    let leaked: &'static str = Box::leak(type_name.clone().into_boxed_str());
                    let flags = PtrFlags::TRUSTED;
                    let ty = if *nullable {
                        RegType::PtrToBtfIdOrNull {
                            id: 0,
                            type_name: leaked,
                            flags,
                            ref_id: None,
                        }
                    } else {
                        RegType::PtrToBtfId {
                            type_name: leaked,
                            flags,
                            ref_id: None,
                        }
                    };
                    state.types.set(*reg, ty);
                    state.domain.forget(*reg);
                }
            }
        }
    }

    // Clear packet size bounds for the callee.
    // The kernel verifier tracks bounds per-function, so each function
    // starts with no proven packet size. This is important for cases where
    // the caller did a bounds check but the callee spills a fresh packet
    // pointer before doing its own check.
    state.domain.clear_packet_size_bounds();

    state.pc = target;

    vec![state]
}

/// Caller-side compatibility for a global subprog arg. The
/// kernel rejects calls whose actual reg type doesn't satisfy the
/// declared kind:
///   - declared Scalar: actual must be ScalarValue.
///   - declared PtrToMem: actual must be a memory-style pointer
///     (PtrToStack / PtrToMapValue / PtrToMem / PtrToAllocMem) OR
///     a scalar that's *provably zero* (literal NULL — the kernel
///     does not admit arbitrary scalars cast to a pointer).
fn caller_arg_compatible<F: Fn() -> bool>(
    declared: &crate::parsing::btf::GlobalFuncArg,
    actual: RegType,
    scalar_is_zero: F,
) -> bool {
    use crate::parsing::btf::GlobalFuncArg;
    match declared {
        GlobalFuncArg::Scalar => matches!(actual, RegType::ScalarValue),
        GlobalFuncArg::PtrToMem { .. } => match actual {
            RegType::PtrToStack { .. }
            | RegType::PtrToMapValue { .. }
            | RegType::PtrToMapValueOrNull { .. }
            | RegType::PtrToAllocMem { .. }
            | RegType::PtrToAllocMemOrNull { .. } => true,
            RegType::ScalarValue => scalar_is_zero(),
            _ => false,
        },
        GlobalFuncArg::PtrToCtx => matches!(actual, RegType::PtrToCtx),
        GlobalFuncArg::PtrToFwd { .. } => false,
        GlobalFuncArg::PtrToBtfIdTrusted {
            nullable,
            type_name,
        } => match actual {
            // `__arg_trusted` accepts any kernel BTF id pointer the
            // caller produced (acquired or static). `__arg_nullable`
            // additionally admits the OrNull variant and literal NULL.
            RegType::PtrToBtfId { .. } => true,
            RegType::PtrToBtfIdOrNull { .. } => *nullable,
            // Acquire-tracked specializations (PtrToTask, PtrToSocket,
            // …) are kernel BTF ids in disguise — accept them when the
            // declared type_name matches. CO-RE flavor suffix
            // (`task_struct___local`) just renames the same kernel
            // type, so strip the trailing `___…` before matching.
            RegType::PtrToTask { .. } | RegType::PtrToTaskOrNull { .. } => {
                let base = type_name.split("___").next().unwrap_or(type_name.as_str());
                base == "task_struct" && (matches!(actual, RegType::PtrToTask { .. }) || *nullable)
            }
            RegType::PtrToSocket { .. } | RegType::PtrToSocketOrNull { .. } => {
                let base = type_name.split("___").next().unwrap_or(type_name.as_str());
                base == "sock" && (matches!(actual, RegType::PtrToSocket { .. }) || *nullable)
            }
            RegType::PtrToCpumask { .. } | RegType::PtrToCpumaskOrNull { .. } => {
                let base = type_name.split("___").next().unwrap_or(type_name.as_str());
                base == "bpf_cpumask"
                    && (matches!(actual, RegType::PtrToCpumask { .. }) || *nullable)
            }
            RegType::ScalarValue => *nullable && scalar_is_zero(),
            _ => false,
        },
        GlobalFuncArg::PtrToDynptr => matches!(actual, RegType::PtrToStack { .. }),
        GlobalFuncArg::PtrToArena => {
            // Mirrors kernel `verifier.c:10370` `ARG_PTR_TO_ARENA`
            // arg-check: accepts `PTR_TO_ARENA` or any `SCALAR_VALUE`
            // (no NULL/zero requirement). Comment in the kernel:
            // "Can pass any value and the kernel won't crash, but only
            // PTR_TO_ARENA or SCALAR make sense." Required for
            // arena_htab_llvm where `htab = bpf_alloc(...)` returns
            // a possibly-null arena pointer and the program calls
            // `htab_update_elem(htab, …)` without a NULL check —
            // both branches reach the call: non-null path with
            // `PtrToArena`, null path with `ScalarValue 0` (or
            // `PtrToArenaOrNull` if the verifier didn't narrow yet).
            // The kernel accepts because `cast_kern` is an LLVM-
            // implicit nop under `__BPF_FEATURE_ADDR_SPACE_CAST`
            // (bpf_arena_common.h:38) — the arena address space is
            // sparse-mapped 4GB and a null arena access faults
            // softly, so the verifier doesn't gate on null-ness here.
            let _ = scalar_is_zero;
            matches!(
                actual,
                RegType::PtrToArena { .. }
                    | RegType::PtrToArenaOrNull { .. }
                    | RegType::ScalarValue
            )
        }
        GlobalFuncArg::PermissivePtr => match actual {
            RegType::PtrToCtx
            | RegType::PtrToStack { .. }
            | RegType::PtrToMapValue { .. }
            | RegType::PtrToMapValueOrNull { .. }
            | RegType::PtrToAllocMem { .. }
            | RegType::PtrToAllocMemOrNull { .. } => true,
            RegType::ScalarValue => scalar_is_zero(),
            _ => false,
        },
    }
}

/// Apply the lock / RCU pre-call flags carried on `proto`.
/// Returns `false` (and calls `env.fail`) if the lock or RCU state
/// machine rejects this call. Arg-shape checks already ran in
/// `validate_helper_args`; here we only mutate `state.active_lock` /
/// `state.rcu_read_depth` and reject mismatched ordering.
pub(crate) fn apply_pre_call_lock_flags(
    env: &mut VerifierEnv,
    state: &mut State,
    helper: u32,
    proto: &super::signatures::CallProto,
) -> bool {
    use super::signatures::CallFlags;
    let pc = state.pc;

    // Helpers/kfuncs marked RCU require an active read-side section.
    if proto.flags.contains(CallFlags::RCU) && !state.in_rcu_read_section() {
        env.fail(VerificationError::NotInRcuReadSection { pc, helper });
        return false;
    }

    // kfuncs marked SPIN_LOCK_HELD (rbtree / list mutation)
    // require any spin_lock to be active. Lite scope doesn't match the
    // lock to a specific map's lock — any held lock satisfies.
    if proto.flags.contains(CallFlags::SPIN_LOCK_HELD) && !state.has_active_lock() {
        env.fail(VerificationError::NotInSpinLockSection { pc, helper });
        return false;
    }

    if proto.flags.contains(CallFlags::SPIN_LOCK_ACQUIRE) {
        if state.has_active_lock() {
            env.fail(VerificationError::LockAlreadyHeld { pc });
            return false;
        }
        // R1 was validated by `validate_map_value_special` as either a
        // PtrToMapValue or a PtrToOwnedKptr aimed at a SpinLock field.
        // The kernel `process_spin_lock` (verifier.c v6.15 L8271+)
        // accepts both shapes; the lock-state-machine identity is
        // (id, offset) for map values and (ref_id, foo_offset) for
        // freshly-allocated objects (`bpf_obj_new`'d struct foo with
        // a `bpf_spin_lock` member). Without this arm, every linked
        // / rbtree test that takes `bpf_spin_lock(&f->lock)` rejects
        // the *_in_list family in linked_list.c).
        let (id, off) = match state.types.get(Reg::R1) {
            RegType::PtrToMapValue {
                offset: Some(o),
                id,
                ..
            } => (id, o as u32),
            RegType::PtrToOwnedKptr { ref_id, offset, .. } => (ref_id.unwrap_or(0), offset as u32),
            _ => {
                env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
                return false;
            }
        };
        state.acquire_lock(id, off);
    }

    if proto.flags.contains(CallFlags::SPIN_LOCK_RELEASE) {
        let id = match state.types.get(Reg::R1) {
            RegType::PtrToMapValue { id, .. } => id,
            RegType::PtrToOwnedKptr { ref_id, .. } => ref_id.unwrap_or(0),
            _ => {
                env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
                return false;
            }
        };
        let Some(lock) = state.get_active_lock() else {
            env.fail(VerificationError::LockNotHeld { pc });
            return false;
        };
        if lock.ptr_id != id {
            env.fail(VerificationError::LockNotHeld { pc });
            return false;
        }
        state.release_lock();
        // Kernel `verifier.c` v6.15 L8382: `process_spin_lock` calls
        // `invalidate_non_owning_refs` on unlock — non-owning refs
        // produced by `bpf_rbtree_add` / `bpf_list_push_*` under this
        // lock are only safe to dereference while the lock is held.
        state.invalidate_non_owning_refs();
    }

    if proto.flags.contains(CallFlags::RCU_READ_LOCK) {
        // Kernel rejects nested `bpf_rcu_read_lock` at the kfunc-arg
        // processing path: a second lock while already in an RCU CS
        // surfaces as "nested rcu_read_lock". Closes
        // rcu_read_lock::nested_rcu_region.
        if state.in_rcu_read_section() {
            env.fail(VerificationError::RcuReadNotHeld { pc });
            return false;
        }
        state.rcu_read_lock();
    }

    if proto.flags.contains(CallFlags::RCU_READ_UNLOCK) {
        if !state.rcu_read_unlock() {
            env.fail(VerificationError::RcuReadNotHeld { pc });
            return false;
        }
        // Kernel verifier.c v6.15 ~L13543: on outermost rcu_read_unlock,
        // every MEM_RCU reg/slot is re-flagged PTR_UNTRUSTED. Mirrored
        // for iter slots and (since this session) for typed BTF
        // pointers, so `bpf_task_storage_get(real_parent)` after
        // unlock rejects on the UNTRUSTED arg.
        if !state.in_rcu_read_section() {
            state.invalidate_rcu_iter_slots();
            state.demote_rcu_btf_regs_to_untrusted();
        }
    }

    // Preempt-region (kernel verifier.c v6.15 ~L13560).
    //
    // MIGHT_SLEEP is checked BEFORE PREEMPT_DISABLE/ENABLE state changes:
    // a sleepable helper inside an existing disabled region rejects
    // regardless of whether this call would itself toggle the count.
    // (`bpf_preempt_disable` and `bpf_preempt_enable` themselves are not
    // marked MIGHT_SLEEP.)
    if proto.flags.contains(CallFlags::MIGHT_SLEEP) && state.in_preempt_disabled() {
        env.fail(VerificationError::SleepableInPreemptDisabled { pc, helper });
        return false;
    }
    // IRQ-disabled region also rejects sleepable calls (kernel
    // verifier.c v6.15 ~L13576).
    if proto.flags.contains(CallFlags::MIGHT_SLEEP) && state.in_irq_disabled() {
        env.fail(VerificationError::IrqState {
            pc,
            reason: "sleepable call inside bpf_local_irq_save-ed region".into(),
        });
        return false;
    }
    // Explicit-RCU-CS region rejects sleepable calls (kernel verifier.c
    // v6.15 L13549: "kernel func %s is sleepable within rcu_read_lock
    // region"). Gated on explicit `bpf_rcu_read_lock` only — the
    // implicit-RCU-at-entry baseline for non-sleepable tracing progs
    // (kprobe/tp/raw_tp/perf_event) is excluded so MIGHT_SLEEP calls
    // from those programs hit the (separate) "non-sleepable context"
    // gates instead.
    let explicit_rcu_baseline = if state.implicit_rcu_at_entry { 1 } else { 0 };
    if proto.flags.contains(CallFlags::MIGHT_SLEEP) && state.rcu_read_depth > explicit_rcu_baseline
    {
        env.fail(VerificationError::SleepableInRcuReadSection { pc, helper });
        return false;
    }

    // bpf_res_spin_unlock{,_irqrestore} (kernel `process_spin_lock`,
    // is_lock=false, verifier.c v6.15 L8358-8379). Validates LIFO match
    // on `acquired_res_locks`; emits the kernel rejection family
    // ("without taking a lock" / "different lock" / "out of order" /
    // wrong-class).
    if proto.flags.contains(CallFlags::RES_SPIN_LOCK_RELEASE) {
        let arg = state.types.get(Reg::R1);
        let (reg_id, ptr_id) = match arg {
            RegType::PtrToMapValue { id, map_idx, .. } => (id, map_idx as u32),
            RegType::PtrToOwnedKptr { ref_id, .. } => (ref_id.unwrap_or(0), 0u32),
            _ => {
                env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
                return false;
            }
        };
        // Distinguish the irqsave flavor from the plain one. We piggy-
        // back on the IRQ_RESTORE side-effect class — this kfunc has
        // `IrqRestoreFromArg { kfunc_class: Lock }` only when it's the
        // irqrestore variant; the plain `_unlock` doesn't.
        let is_irq = proto.side_effects.iter().any(|e| {
            matches!(
                e,
                super::signatures::SideEffect::IrqRestoreFromArg {
                    kfunc_class: crate::analysis::machine::stack_state::IrqKfuncClass::Lock,
                    ..
                }
            )
        });
        match state.res_lock_release(reg_id, ptr_id, is_irq) {
            Ok(()) => {}
            Err(crate::analysis::machine::state::ResLockReleaseError::Empty) => {
                env.fail(VerificationError::LockNotHeld { pc });
                return false;
            }
            Err(_) => {
                // NotInStack / OutOfOrder / WrongClass — single error
                // variant; specific kernel message string is lost but
                // the rejection (and per-test classification) matches.
                env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
                return false;
            }
        }
    }

    if proto.flags.contains(CallFlags::PREEMPT_DISABLE) {
        state.preempt_disable();
    }

    if proto.flags.contains(CallFlags::PREEMPT_ENABLE) && !state.preempt_enable() {
        env.fail(VerificationError::PreemptNotDisabled { pc });
        return false;
    }

    // IRQ_SAVE / IRQ_RESTORE: validator already checked the arg type;
    // the side-effect handler mutates the state. We only set up the
    // gate here for completeness symmetry — actual mutation is in
    // `apply_call_proto_r0`'s side-effect loop.
    // (No state changes here; gating belongs to the proto path's
    // arg validator + side-effect applier.)

    true
}

pub(crate) fn interval_set_scalar_id(domain: &mut NumericDomain, reg: Reg) {
    if let NumericDomain::Interval(ivl) = domain {
        ivl.get_bounds_mut(reg).scalar_id = Some(new_scalar_id());
    }
}

pub(crate) fn restore_interval_ptr_offset_from_return(
    domain: &mut NumericDomain,
    ret_type: &RegType,
    ret_interval_ptr_offset: (Option<i64>, Option<u64>, Option<i64>, Option<u32>),
) {
    if let (Some(off), var_off_opt, range, id) = ret_interval_ptr_offset {
        use crate::domains::interval::PtrOffset;

        // Determine anchor from register type
        let anchor = match ret_type {
            RegType::PtrToPacket => Some(Reg::AnchorData),
            RegType::PtrToPacketMeta => Some(Reg::AnchorDataMeta),
            RegType::PtrToPacketEnd => Some(Reg::AnchorDataEnd),
            _ => None,
        };

        if let Some(anchor) = anchor
            && let NumericDomain::Interval(ivl) = domain
        {
            let var_off = var_off_opt.unwrap_or(0);
            let ptr_offset = PtrOffset {
                anchor,
                off,
                var_off,
                range,
                // id round-trips across subprog returns (kernel
                // keeps the full reg state incl. id).
                id,
                // mark_pkt_end relationship not round-tripped across
                // subprog returns; conservative None is sound.
                pkt_end_rel: None,
            };
            ivl.get_mut(Reg::R0).ptr_offset = Some(ptr_offset);
        }
    }
}

pub(crate) fn restore_callee_interval_packet_info(
    domain: &mut NumericDomain,
    caller_types: &crate::analysis::machine::reg_types::TypeState,
    callee_saved_packet_info: Vec<(
        Reg,
        RegType,
        (Option<i64>, Option<u64>, Option<i64>, Option<u32>),
    )>,
) {
    for (reg, callee_type, (off_opt, var_off_opt, range, _id)) in callee_saved_packet_info {
        if let (Some(off), Some(range_val)) = (off_opt, range) {
            let anchor = match callee_type {
                RegType::PtrToPacket => Some(Reg::AnchorData),
                RegType::PtrToPacketMeta => Some(Reg::AnchorDataMeta),
                _ => None,
            };

            if let Some(anchor) = anchor
                && matches!(
                    caller_types.get(reg),
                    RegType::PtrToPacket | RegType::PtrToPacketMeta
                )
                && let NumericDomain::Interval(ivl) = domain
                && let Some(caller_ptr_off) = ivl.get_ptr_offset(reg)
                && caller_ptr_off.anchor == anchor
                && caller_ptr_off.off == off
                && caller_ptr_off.var_off == var_off_opt.unwrap_or(0)
            {
                let caller_range = caller_ptr_off.range.unwrap_or(0);
                if range_val > caller_range {
                    let mut new_ptr_off = *caller_ptr_off;
                    new_ptr_off.range = Some(range_val);
                    ivl.get_mut(reg).ptr_offset = Some(new_ptr_off);
                }
            }
        }
    }
}
