// src/analysis/transfer/call/kfunc.rs
//
// Kfunc call transfer.
//
// As of the only bespoke handler left is `bpf_throw` (terminal
// control flow — drops the path with no successor). Every other kfunc
// is driven by `CallProto` via the unified pipeline in `signatures` /
// `checks` / `side_effects`. Forking kfuncs (`bpf_iter_*_next`) are
// recognized via `RetKind::IterNextElem` and split into two successors
// inside `transfer_kfunc_proto`.

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::error::VerificationError;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::{RegType, TypeState, new_ptr_id};
use crate::analysis::machine::stack_state::{IterState, IteratorSlot};
use crate::analysis::machine::state::State;
use crate::domains::tnum::Tnum;

use super::side_effects::{apply_call_proto_r0, arg_reg, resolve_stack_arg};
use super::signatures::{CallFlags, CallProto, RetKind, SideEffect, get_kfunc_proto};

/// Top-level kfunc dispatch. Looks up the kfunc name in BTF and routes
/// it. Resolution order:
///
///   1. `get_kfunc_proto(name)` — proto-driven path. The generic
///      checker + shared post-call applier in `side_effects.rs` handles
///      arg validation, R0 typing, side effects, and (for the iter_next
///      family) the two-successor fork.
///   2. `bpf_throw` — bespoke because it's terminal (no successor) and
///      doesn't fit the flat proto model.
///   3. Unknown kfunc → REJECT.
pub(crate) fn transfer_kfunc(env: &mut VerifierEnv, state: State, btf_id: u32) -> Vec<State> {
    let pc = state.pc;
    let name = env.ctx.btf.kfunc_name(btf_id).map(|s| s.to_string());

    if let Some(n) = name.as_deref()
        && let Some(proto) = get_kfunc_proto(n)
    {
        // Kernel `check_css_task_iter_allowlist` (verifier.c v6.15
        // ~L13151): bpf_iter_css_task_new is only allowed in BPF_LSM,
        // BPF_TRACE_ITER, and sleepable programs — rejected with
        // "css_task_iter is only allowed in bpf_lsm, bpf_iter and
        // sleepable progs" otherwise. Closes
        // iters_task_failure.c::iter_css_task_for_each (the
        // SEC("?fentry/...") non-sleepable variant).
        if n == "bpf_iter_css_task_new" {
            use crate::ast::ProgramKind;
            let allowed = env.ctx.prog_kind == ProgramKind::Lsm
                || matches!(env.ctx.attach_flavor.as_deref(), Some("iter"))
                || env.ctx.is_sleepable;
            if !allowed {
                env.fail(VerificationError::KfuncNotAllowedForProgram {
                    pc,
                    btf_id,
                    kind: env.ctx.prog_kind,
                });
                return vec![];
            }
        }

        // Kernel registers bpf_sock_destroy via bpf_sk_iter_kfunc_set
        // against BPF_PROG_TYPE_TRACING with KF_PROG_TYPE_BPF_TRACE_ITER —
        // only iter/{tcp,udp} attach types may call it. Tracing programs
        // attached at tp_btf etc. are rejected with the kernel's
        // "calling kernel function bpf_sock_destroy is not allowed".
        // Closes sock_destroy_prog_fail.c::trace_tcp_destroy_sock surfaced
        // by the new bpf_sock_destroy proto registration.
        if n == "bpf_sock_destroy" && !matches!(env.ctx.attach_flavor.as_deref(), Some("iter")) {
            env.fail(VerificationError::KfuncNotAllowedForProgram {
                pc,
                btf_id,
                kind: env.ctx.prog_kind,
            });
            return vec![];
        }
        return transfer_kfunc_proto(env, state, btf_id, &proto);
    }

    match name.as_deref() {
        // `bpf_throw` is terminal on this path. Stays bespoke
        // because the proto applier always produces at least one
        // continuing successor.
        Some("bpf_throw") => throw(env, state),

        _ => {
            env.fail(VerificationError::UnsupportedModernFeature {
                pc,
                feature: "kfunc call (BPF_PSEUDO_KFUNC_CALL)",
            });
            vec![]
        }
    }
}

/// Generic kfunc transfer driven by `CallProto`. Mirrors the helper
/// post-call sequence in `transfer_call`: validate args → apply side
/// effects + R0 → clobber caller-saved → advance pc.
///
/// `RetKind::IterNextElem` is the lone forking case: args and
/// non-r0 side effects run on a shared base; then we split into two
/// successors that get independent R0 typing + slot-state transitions.
fn transfer_kfunc_proto(
    env: &mut VerifierEnv,
    mut state: State,
    btf_id: u32,
    proto: &CallProto,
) -> Vec<State> {
    let pc = state.pc;
    let in_types = state.types.clone();

    if !validate_kfunc_allowlists(env, proto, pc, btf_id) {
        return vec![];
    }

    if !super::mem_checks::check_mem_size_pairs(env, &state, proto, pc) {
        return vec![];
    }

    // Kernel: `bpf_rcu_read_{lock,unlock}` cross a spin_lock boundary
    // is rejected as "function calls are not allowed while holding a
    // lock" (refcounted_kptr_fail::rbtree_fail_sleepable_lock_across_rcu).
    // The kfunc has no lock-aware semantics — programs that toggle
    // RCU regions while a spin_lock is held would unwind the lock
    // pairing across critical sections.
    if state.has_active_lock()
        && (proto.flags.contains(CallFlags::RCU_READ_LOCK)
            || proto.flags.contains(CallFlags::RCU_READ_UNLOCK))
    {
        env.fail(
            crate::analysis::machine::error::VerificationError::InvalidArgType { pc, reg: Reg::R0 },
        );
        return vec![];
    }

    // enforce SPIN_LOCK_HELD / RCU / lock-acquire-release proto
    // flags before arg validation. Done here (not in side_effects)
    // because rejection short-circuits the whole call.
    if !super::transfer::apply_pre_call_lock_flags(env, &mut state, btf_id, proto) {
        return vec![];
    }

    let arg_regs = [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5];
    for (i, (&arg_kind, &reg)) in proto.args.iter().zip(arg_regs.iter()).enumerate() {
        if matches!(arg_kind, super::signatures::ArgKind::DontCare) {
            break;
        }
        let actual = in_types.get(reg);
        if !super::checks::validate_single_arg(
            env,
            &state,
            &in_types,
            /* helper */ 0,
            pc,
            reg,
            arg_kind,
            actual,
            &None,
            i,
            proto.mem_size_pairs,
        ) {
            return vec![];
        }
    }

    // Graph-mutation `__contains` cross-arg check: for
    // `bpf_list_push_{front,back}_impl` and `bpf_rbtree_add_impl`,
    // R1 is the head (PtrToMapValue at the head's offset within a map
    // value carrying a `bpf_list_head` / `bpf_rb_root` field decorated
    // with `__contains(<struct>, <member>)`). R2 is the node, a
    // `PtrToOwnedKptr` whose `offset` must equal the contained
    // struct's `<member>` byte offset.
    //
    // Lite scope (this commit): offset comparison only — closes the
    // `incorrect_node_off*` family in `linked_list_fail.c`. The
    // companion struct-type check (no_node_value_type,
    // incorrect_value_type) needs `pointee_btf_id` on PtrToOwnedKptr,
    // which is a separate representation change.
    {
        let kfunc_name = env.ctx.btf.kfunc_name(btf_id).map(|s| s.to_string());
        let is_graph_add = matches!(
            kfunc_name.as_deref(),
            Some("bpf_list_push_front_impl")
                | Some("bpf_list_push_back_impl")
                | Some("bpf_rbtree_add_impl")
        );
        if is_graph_add
            && let RegType::PtrToMapValue {
                offset: Some(head_off),
                map_idx,
                ..
            } = in_types.get(Reg::R1)
            && let RegType::PtrToOwnedKptr {
                offset: node_off,
                pointee_btf_id,
                ..
            } = in_types.get(Reg::R2)
            && let Some(map_def) = env.ctx.map_defs.get(map_idx)
            && let Some(val_type_id) = map_def.btf_val_type_id
        {
            let fields = env.ctx.btf.find_special_fields(val_type_id);
            if let Some(field) = fields.iter().find(|f| f.offset as i64 == head_off)
                && let Some(contains) = field.contains.as_ref()
            {
                let off_mismatch = match contains.node_offset {
                    Some(n) => (node_off as i64) != n as i64,
                    None => false,
                };
                // Pointee-struct check: when the node carries a known
                // pointee_btf_id (planted by bpf_obj_new_impl /
                // bpf_refcount_acquire / list+rbtree pop kfuncs), reject
                // when its struct name doesn't match the head's
                // `__contains(<struct>, ...)` declaration. Closes
                // rbtree_btf_fail__add_wrong_type, where node_data2's
                // node-member offset coincidentally matches node_data's
                // declared offset (both 8); only the struct identity
                // distinguishes them. None ⇒ unknown pointee, fall back
                // to offset-only check (preserves prior behavior for
                // `bpf_rbtree_first` whose pointee threading is lite).
                let type_mismatch = match pointee_btf_id {
                    Some(id) => env
                        .ctx
                        .btf
                        .struct_name(id)
                        .map(|n| n != contains.struct_name.as_str())
                        .unwrap_or(false),
                    None => false,
                };
                if off_mismatch || type_mismatch {
                    env.fail(
                        crate::analysis::machine::error::VerificationError::InvalidArgType {
                            pc,
                            reg: Reg::R2,
                        },
                    );
                    return vec![];
                }
            }
        }
    }

    // KF_RELEASE precondition: every `ReleaseRefFromArg{N}` arg must be a
    // refcounted pointer (i.e. carry a `ref_id`). Kernel rejects calls
    // like `bpf_put_file(file)` on a non-acquired (e.g. BPF_PROG entry)
    // pointer with "release kernel function bpf_put_file expects
    // refcounted PTR_TO_BTF_ID". Without this gate, our generic
    // `PtrToBtfId` validator (which doesn't inspect ref_id) would accept
    // and the side-effect's get_ref_id-then-release would silently
    // no-op on `ref_id: None`. The pre-existing `BPF_SK_RELEASE` arm in
    // `transfer.rs` handles the helper case with the same shape; this
    // closes the gap for the unified kfunc dispatcher.
    // Callback-misuse static scan: graph-add kfuncs (rbtree_add /
    // list_push_*) take a `less` callback in R3. The kernel rejects
    // when the cb body contains forbidden ops (spin_lock/unlock,
    // bpf_throw, recursive graph-mutation kfuncs, alloc/release).
    // Lite scope: any subprog landed in `tainted_cb_subprogs` at env
    // init is rejected here. Without this, the static-MapValue id=0
    // change unmasks several rbtree_fail / exceptions_fail
    // FALSE_ACCEPTs.
    if proto.flags.contains(CallFlags::RELEASE_NON_OWN) {
        // Cb arg by convention is R3 for both rbtree_add and list_push.
        if let RegType::PtrToCallback { subprog_pc } = in_types.get(Reg::R3)
            && env.tainted_cb_subprogs.contains(&(subprog_pc as usize))
        {
            env.fail(
                crate::analysis::machine::error::VerificationError::InvalidArgType {
                    pc,
                    reg: Reg::R3,
                },
            );
            return vec![];
        }
    }

    // ---- bpf_wq family cross-arg + callback-fork dispatch ----
    //
    // Done by name lookup since the kfunc family doesn't fit the generic
    // proto + side-effects model:
    //   * `bpf_wq_init` cross-arg: kernel rejects when R1's owning
    //     map_uid != R2's map_uid ("workqueue pointer in R1 map_uid=N
    //     doesn't match map pointer in R2 map_uid=M") — keeps
    //     wq_failures::test_wq_init_wrong_map FA-safe. Coarse map_idx
    //     equality (we don't track map_uid) is sufficient because every
    //     map declared in a single ELF gets a distinct map_idx.
    //   * `bpf_wq_set_callback_impl` callback-fork: cb runs async, so
    //     registration requires no held locks / unreleased refs (mirrors
    //     BPF_TIMER_SET_CALLBACK). The cb signature is
    //     `(map, key, value)` typed from caller's R1 (wq's owning
    //     map_idx).
    {
        let kfunc_name = env.ctx.btf.kfunc_name(btf_id);
        if kfunc_name == Some("bpf_wq_init") {
            if let (
                RegType::PtrToMapValue {
                    map_idx: wq_map, ..
                },
                RegType::PtrToMapObject { map_idx: ptr_map },
            ) = (in_types.get(Reg::R1), in_types.get(Reg::R2))
                && wq_map != ptr_map
            {
                env.fail(
                    crate::analysis::machine::error::VerificationError::InvalidArgType {
                        pc,
                        reg: Reg::R2,
                    },
                );
                return vec![];
            }
        } else if kfunc_name == Some("bpf_wq_set_callback_impl") {
            return transfer_kfunc_wq_set_callback(env, &in_types, state, btf_id, proto);
        }
    }

    if !handle_kfunc_release(env, &in_types, &state, proto, pc, &arg_regs) {
        return vec![];
    }

    if !enforce_kfunc_trust_band(env, &in_types, proto, pc, &arg_regs) {
        return vec![];
    }

    // Forking kfuncs (iter_next): handle the two successors inline so
    // each can carry its own R0 typing and slot-state transition.
    match proto.ret {
        RetKind::IterNextElem {
            iter_arg,
            elem_size,
        } => {
            return iter_next_fork(env, state, iter_arg, IterNextElemKind::AllocMem(elem_size));
        }
        RetKind::IterNextBtfId {
            iter_arg,
            type_name,
            flags,
        } => {
            return iter_next_fork(
                env,
                state,
                iter_arg,
                IterNextElemKind::BtfId { type_name, flags },
            );
        }
        _ => {}
    }

    // bpf_res_spin_lock{,_irqsave}: state-fork at the call site
    // (kernel `push_stack`, verifier.c v6.15 L13455-13479). Success
    // branch: R0 = 0, lock pushed on `acquired_res_locks`. Failure
    // branch: R0 ∈ [-MAX_ERRNO, -1] (we approximate as ≤ -1 on the
    // signed-32 axis), no lock pushed. AA-deadlock detection runs on
    // the success-branch push (kernel L8331-8336).
    if proto.flags.contains(CallFlags::RES_SPIN_LOCK_ACQUIRE) {
        let arg = in_types.get(Reg::R1);
        let (reg_id, ptr_id) = match arg {
            RegType::PtrToMapValue { id, map_idx, .. } => (id, map_idx as u32),
            RegType::PtrToOwnedKptr { ref_id, .. } => (ref_id.unwrap_or(0), 0u32),
            _ => {
                env.fail(
                    crate::analysis::machine::error::VerificationError::InvalidArgType {
                        pc,
                        reg: Reg::R1,
                    },
                );
                return vec![];
            }
        };
        // AA detection (kernel L8331-8336).
        if state.res_lock_already_held(reg_id, ptr_id) {
            env.fail(
                crate::analysis::machine::error::VerificationError::InvalidArgType {
                    pc,
                    reg: Reg::R1,
                },
            );
            return vec![];
        }
        let is_irq = proto.side_effects.iter().any(|e| {
            matches!(
                e,
                SideEffect::IrqSaveOnArg {
                    kfunc_class: crate::analysis::machine::stack_state::IrqKfuncClass::Lock,
                    ..
                }
            )
        });
        // Failure branch: clone state BEFORE pushing lock, set R0 < 0.
        // Note: irqsave's IrqSaveOnArg side-effect would also have
        // stamped the irq-flag slot. The kernel's failure branch
        // skips push_stack for the irq flag slot too (only the
        // success branch is "in critical section"). We approximate
        // by running side-effects only on the success state below.
        let mut fail = state.clone();
        // Emulate apply_call_proto_r0 for the failure branch but bound
        // R0 to the kernel's actual error range `[-MAX_ERRNO, -1]`
        // (kernel `bpf_res_spin_lock` returns `-EDEADLK`/`-ETIMEDOUT`,
        // and the verifier models the failure path's R0 as a negative
        // errno bounded by `[-MAX_ERRNO, -1]`). The full range — not a
        // bare `<= -1` — is what lets the common idiom
        // `r = bpf_res_spin_lock(&l); if ((int)r) /* fail */`
        // (the compiler truncates `r` to 32 bits, `if w0 != 0`) prove
        // the failure arm: with R0 in `[-4095, -1]` the low 32 bits are
        // `[0xFFFFF001, 0xFFFFFFFF]`, all non-zero, so `if w0 != 0` is
        // provably taken on the failure path and the matching unlock is
        // not reached with a stale lock stack. A bare `<= -1` admits
        // e.g. `-2^32` whose low 32 bits are 0, so the fall-through
        // (success-coded) arm stays live and a LIFO unlock check
        // false-rejects. Tightening (narrower range) ⇒ FA-safe.
        fail.types.set(Reg::R0, RegType::ScalarValue);
        fail.domain.forget(Reg::R0);
        fail.set_tnum(Reg::R0, Tnum::unknown());
        fail.clear_scalar_id(Reg::R0);
        fail.domain
            .assume_range(Reg::R0, -crate::common::constants::MAX_ERRNO, -1);
        // Caller-saved clobber on failure branch to match the
        // post-call sequence below.
        if !proto.flags.contains(CallFlags::FASTCALL) {
            for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
                fail.types.set(r, RegType::NotInit);
                fail.domain.forget(r);
                fail.set_tnum(r, Tnum::unknown());
                fail.clear_scalar_id(r);
                fail.ptr_const_off.remove(&r);
                fail.var_off_contributor.remove(&r);
            }
        }
        fail.ptr_const_off.remove(&Reg::R0);
        fail.var_off_contributor.remove(&Reg::R0);
        fail.pc += 1;

        // Success branch: push the lock, run the existing
        // post-call sequence below. Side-effects (IrqSaveOnArg for
        // irqsave) ran already on the original `state` via
        // apply_side_effects above; we leave them in place.
        state.res_lock_acquire(reg_id, ptr_id, is_irq);
        apply_call_proto_r0(&in_types, &mut state, proto, env.ctx.prog_kind);
        // Success branch's R0 is the kfunc-return scalar — but
        // semantically it's 0. Pin to a proven-zero scalar so the
        // typical `if (bpf_res_spin_lock(&l)) return …;` correctly
        // takes the fall-through (non-zero) branch as DEAD on the
        // success path.
        state.domain.assume_eq_imm(Reg::R0, 0);
        state.set_tnum(Reg::R0, Tnum::constant(0));
        if !proto.flags.contains(CallFlags::FASTCALL) {
            for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
                state.types.set(r, RegType::NotInit);
                state.domain.forget(r);
                state.set_tnum(r, Tnum::unknown());
                state.clear_scalar_id(r);
                state.ptr_const_off.remove(&r);
                state.var_off_contributor.remove(&r);
            }
        }
        state.ptr_const_off.remove(&Reg::R0);
        state.var_off_contributor.remove(&Reg::R0);
        state.pc += 1;
        return vec![state, fail];
    }

    apply_call_proto_r0(&in_types, &mut state, proto, env.ctx.prog_kind);

    // (Cross-arg + callback-fork dispatch above intercepts
    // bpf_wq_set_callback_impl before this point — we never reach here
    // for it, so the post-call sequence below applies cleanly to
    // bpf_wq_init / bpf_wq_start which are flat-shaped kfuncs.)

    if !apply_kfunc_name_specific_ret(env, &mut state, btf_id, &in_types) {
        return vec![];
    }

    // kfuncs marked `bpf_fastcall` (v6.13) preserve R1..R5 — skip
    // the caller-saved clobber so clang-emitted no-spill sequences
    // type-check. Iter-next forks intentionally always clobber (no
    // fastcall iter_next kfunc exists in the kernel set).
    if !proto.flags.contains(CallFlags::FASTCALL) {
        for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
            state.types.set(r, RegType::NotInit);
            state.domain.forget(r);
            state.set_tnum(r, Tnum::unknown());
            state.clear_scalar_id(r);
            state.ptr_const_off.remove(&r);
            state.var_off_contributor.remove(&r);
        }
    }
    // Same caller-saved side-map scrub as the helper path (kernel
    // check_kfunc_call caller_saved reset, verifier.c:14536): R0 is
    // wholly redefined by the kfunc return.
    state.domain.forget(Reg::R0);
    state.set_tnum(Reg::R0, Tnum::unknown());
    state.clear_scalar_id(Reg::R0);
    state.ptr_const_off.remove(&Reg::R0);
    state.var_off_contributor.remove(&Reg::R0);

    state.pc += 1;
    vec![state]
}

/// Checks the per-kfunc prog-type and ops-member allowlists.
/// Returns false (and calls env.fail) if the current program kind or
/// struct_ops binding is not in the proto's allowlist.
fn validate_kfunc_allowlists(
    env: &mut VerifierEnv,
    proto: &super::signatures::CallProto,
    pc: usize,
    btf_id: u32,
) -> bool {
    if let Some(allowed) = proto.prog_type_allowlist
        && !allowed.contains(&env.ctx.prog_kind)
    {
        env.fail(
            crate::analysis::machine::error::VerificationError::KfuncNotAllowedForProgram {
                pc,
                btf_id,
                kind: env.ctx.prog_kind,
            },
        );
        return false;
    }

    if let Some(allowed) = proto.ops_member_allowlist
        && env.ctx.prog_kind == crate::ast::ProgramKind::StructOps
    {
        let ok = match &env.ctx.struct_ops_member {
            Some((ops, member)) => allowed
                .iter()
                .any(|(o, m)| *o == ops.as_str() && *m == member.as_str()),
            None => false,
        };
        if !ok {
            let (ops_struct, member) = env
                .ctx
                .struct_ops_member
                .clone()
                .unwrap_or_else(|| ("?".to_string(), "?".to_string()));
            env.fail(
                crate::analysis::machine::error::VerificationError::KfuncNotAllowedForOpsMember {
                    pc,
                    btf_id,
                    ops_struct,
                    member,
                },
            );
            return false;
        }
    }
    true
}

/// Enforces KF_RELEASE preconditions: every `ReleaseRefFromArg{N}` arg
/// must carry a live ref_id and non-positive offset for full-release kfuncs.
fn handle_kfunc_release(
    env: &mut VerifierEnv,
    in_types: &TypeState,
    state: &State,
    proto: &super::signatures::CallProto,
    pc: usize,
    arg_regs: &[Reg; 5],
) -> bool {
    if !proto.flags.contains(super::signatures::CallFlags::RELEASE) {
        return true;
    }
    let is_non_own = proto
        .flags
        .contains(super::signatures::CallFlags::RELEASE_NON_OWN);
    for eff in proto.side_effects {
        if let super::signatures::SideEffect::ReleaseRefFromArg { arg } = *eff {
            let reg = arg_regs[arg as usize];
            let actual = in_types.get(reg);
            if actual.get_ref_id().is_none() {
                env.fail(
                    crate::analysis::machine::error::VerificationError::InvalidArgType { pc, reg },
                );
                return false;
            }
            if let Some(rid) = actual.get_ref_id()
                && !state.active_refs.contains(&rid)
            {
                env.fail(
                    crate::analysis::machine::error::VerificationError::InvalidArgType { pc, reg },
                );
                return false;
            }
            if !is_non_own
                && let RegType::PtrToOwnedKptr { offset, .. } = actual
                && offset > 0
            {
                env.fail(
                    crate::analysis::machine::error::VerificationError::InvalidArgType { pc, reg },
                );
                return false;
            }
        }
    }
    true
}

/// Enforces KF_TRUSTED_ARGS / KF_RCU: BTF-typed pointer args must
/// satisfy the kfunc's trust band. Non-pointer and memory-buffer args
/// are exempt (they don't go through the kernel's trust-check path).
fn enforce_kfunc_trust_band(
    env: &mut VerifierEnv,
    in_types: &TypeState,
    proto: &super::signatures::CallProto,
    pc: usize,
    arg_regs: &[Reg; 5],
) -> bool {
    use super::signatures::{ArgKind, CallFlags};

    let trust_band = if proto.flags.contains(CallFlags::TRUSTED_ARGS) {
        Some(TrustBand::Trusted)
    } else if proto.flags.contains(CallFlags::RCU) {
        Some(TrustBand::Rcu)
    } else {
        None
    };
    let Some(band) = trust_band else {
        return true;
    };
    for (i, (&arg_kind, &reg)) in proto.args.iter().zip(arg_regs.iter()).enumerate() {
        if matches!(arg_kind, ArgKind::DontCare) {
            break;
        }
        let trust_irrelevant = matches!(
            arg_kind,
            ArgKind::PtrToUninitMem
                | ArgKind::PtrToUninitMemOrNull
                | ArgKind::PtrToMem
                | ArgKind::PtrToMemOrNull
                | ArgKind::PtrToStack
                | ArgKind::PtrToStackOrNull
                | ArgKind::ConstSize
                | ArgKind::ConstSizeOrZero
                | ArgKind::ConstAllocSizeOrZero
                | ArgKind::PtrToConstStr
                | ArgKind::PtrToLong
                | ArgKind::DynptrArg { .. }
                | ArgKind::IterArg { .. }
                | ArgKind::IrqFlagArg { .. }
                | ArgKind::ResSpinLockArg { .. }
                | ArgKind::MapValueSpecial { .. }
        );
        if trust_irrelevant {
            continue;
        }
        let actual = in_types.get(reg);
        if actual.is_pointer() && !pointer_arg_meets_trust(&actual, band) {
            let _ = i;
            env.fail(
                crate::analysis::machine::error::VerificationError::InvalidArgType { pc, reg },
            );
            return false;
        }
    }
    true
}

/// Applies kfunc-name-specific R0 fixups after `apply_call_proto_r0`.
/// Covers: pointee BTF-id threading for graph-manipulation kfuncs,
/// bpf_percpu_obj_drop_impl validation, bpf_percpu_obj_new_impl R0,
/// bpf_cast_to_kern_ctx R0, and bpf_rdonly_cast R0.
/// Returns false (and calls env.fail) on pre-call validation failure.
fn apply_kfunc_name_specific_ret(
    env: &mut VerifierEnv,
    state: &mut State,
    btf_id: u32,
    in_types: &TypeState,
) -> bool {
    use crate::analysis::machine::error::VerificationError;

    let pc = state.pc;

    // Pointee BTF-id threading for graph-manipulation kfuncs.
    if let Some(kfunc_name) = env.ctx.btf.kfunc_name(btf_id) {
        let (pointee, node_offset_override): (Option<u32>, Option<i32>) = match kfunc_name {
            "bpf_obj_new_impl" => (
                state
                    .domain
                    .get_fixed_value(Reg::R1)
                    .and_then(|v| u32::try_from(v).ok()),
                None,
            ),
            "bpf_refcount_acquire_impl" => match in_types.get(Reg::R1) {
                RegType::PtrToOwnedKptr { pointee_btf_id, .. } => (pointee_btf_id, None),
                _ => (None, None),
            },
            "bpf_list_pop_front" | "bpf_list_pop_back" | "bpf_rbtree_first"
            | "bpf_rbtree_remove" => {
                if let RegType::PtrToMapValue {
                    offset: Some(head_off),
                    map_idx,
                    ..
                } = in_types.get(Reg::R1)
                    && let Some(map_def) = env.ctx.map_defs.get(map_idx)
                    && let Some(val_type_id) = map_def.btf_val_type_id
                {
                    let fields = env.ctx.btf.find_special_fields(val_type_id);
                    let contains = fields
                        .iter()
                        .find(|f| f.offset as i64 == head_off)
                        .and_then(|f| f.contains.as_ref());
                    let pointee =
                        contains.and_then(|c| env.ctx.btf.find_struct_by_name(&c.struct_name));
                    let node_off = contains
                        .and_then(|c| c.node_offset)
                        .and_then(|n| i32::try_from(n).ok());
                    (pointee, node_off)
                } else {
                    (None, None)
                }
            }
            _ => (None, None),
        };
        if let Some(new_btf_id) = pointee {
            match state.types.get(Reg::R0) {
                RegType::PtrToOwnedKptr {
                    ref_id,
                    offset,
                    non_owning,
                    ..
                } => {
                    state.types.set(
                        Reg::R0,
                        RegType::PtrToOwnedKptr {
                            ref_id,
                            offset: node_offset_override.unwrap_or(offset),
                            non_owning,
                            pointee_btf_id: Some(new_btf_id),
                        },
                    );
                }
                RegType::PtrToOwnedKptrOrNull { ref_id, offset, .. } => {
                    state.types.set(
                        Reg::R0,
                        RegType::PtrToOwnedKptrOrNull {
                            ref_id,
                            pointee_btf_id: Some(new_btf_id),
                            offset: node_offset_override.unwrap_or(offset),
                        },
                    );
                }
                _ => {}
            }
        }
    }

    // bpf_percpu_obj_drop_impl: R1 must be a percpu pointer with a live ref.
    if let Some(kfunc_name) = env.ctx.btf.kfunc_name(btf_id)
        && kfunc_name == "bpf_percpu_obj_drop_impl"
    {
        use crate::analysis::machine::reg_types::PtrFlags;
        let r1 = in_types.get(Reg::R1);
        let percpu_ok = matches!(
            r1,
            RegType::PtrToBtfId { .. }
                | RegType::PtrToBtfIdOrNull { .. }
                | RegType::PtrToMapKptr { .. }
                | RegType::PtrToMapKptrOrNull { .. }
        ) && r1.ptr_flags().contains(PtrFlags::PERCPU)
            && r1.get_ref_id().is_some();
        if !percpu_ok {
            env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
            return false;
        }
    }

    // bpf_percpu_obj_new_impl: validate struct constraints, set R0.
    if let Some(kfunc_name) = env.ctx.btf.kfunc_name(btf_id)
        && kfunc_name == "bpf_percpu_obj_new_impl"
    {
        use crate::analysis::machine::context::intern_btf_type_name_strict;
        use crate::analysis::machine::reg_types::PtrFlags;
        let local_type_id = state
            .domain
            .get_fixed_value(Reg::R1)
            .and_then(|v| u32::try_from(v).ok());
        if let Some(id) = local_type_id {
            if env.ctx.btf.type_size_bytes(id) > 512 {
                env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
                return false;
            }
            if env.ctx.btf.struct_contains_pointer(id) {
                env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
                return false;
            }
            if !env.ctx.btf.find_special_fields(id).is_empty() {
                env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R1 });
                return false;
            }
        }
        let type_name = local_type_id
            .and_then(|id| env.ctx.btf.struct_name(id))
            .map(intern_btf_type_name_strict)
            .unwrap_or("unknown");
        let ref_id = state.acquire_ref();
        state.types.set(
            Reg::R0,
            RegType::PtrToBtfIdOrNull {
                id: new_ptr_id(),
                type_name,
                flags: PtrFlags::TRUSTED | PtrFlags::PERCPU | PtrFlags::MEM_ALLOC,
                ref_id: Some(ref_id),
            },
        );
    }

    // bpf_cast_to_kern_ctx: R0 = PtrToBtfId{kern_ctx_type_name, TRUSTED}.
    if let Some(kfunc_name) = env.ctx.btf.kfunc_name(btf_id)
        && kfunc_name == "bpf_cast_to_kern_ctx"
    {
        use crate::analysis::machine::reg_types::PtrFlags;
        use crate::ast::ProgramKind;
        let kern_name: Option<&'static str> = match env.ctx.prog_kind {
            ProgramKind::Xdp => Some("xdp_buff"),
            ProgramKind::SchedCls
            | ProgramKind::SchedAct
            | ProgramKind::SocketFilter
            | ProgramKind::CgroupSkb
            | ProgramKind::SkSkb
            | ProgramKind::LwtIn
            | ProgramKind::LwtOut
            | ProgramKind::LwtXmit
            | ProgramKind::FlowDissector => Some("sk_buff"),
            ProgramKind::CgroupSockAddr => Some("bpf_sock_addr_kern"),
            ProgramKind::CgroupSock => Some("sock"),
            ProgramKind::CgroupSockopt => Some("bpf_sockopt_kern"),
            ProgramKind::SockOps => Some("bpf_sock_ops_kern"),
            ProgramKind::SkLookup => Some("bpf_sk_lookup_kern"),
            ProgramKind::SkMsg => Some("sk_msg"),
            ProgramKind::SkReuseport => Some("sk_reuseport_kern"),
            ProgramKind::PerfEvent => Some("bpf_perf_event_data_kern"),
            _ => None,
        };
        match kern_name {
            Some(name) => {
                let interned = crate::analysis::machine::context::intern_btf_type_name_strict(name);
                state.types.set(
                    Reg::R0,
                    RegType::PtrToBtfId {
                        type_name: interned,
                        flags: PtrFlags::TRUSTED,
                        ref_id: None,
                    },
                );
            }
            None => {
                state.types.set(Reg::R0, RegType::ScalarValue);
            }
        }
    }

    // bpf_rdonly_cast: R0 = PtrToBtfId{name(R2_btf_id), TRUSTED|RDONLY}.
    if let Some(kfunc_name) = env.ctx.btf.kfunc_name(btf_id)
        && kfunc_name == "bpf_rdonly_cast"
    {
        use crate::analysis::machine::reg_types::PtrFlags;
        let r2_id = state
            .domain
            .get_fixed_value(Reg::R2)
            .and_then(|v| u32::try_from(v).ok());
        if let Some(target_id) = r2_id
            && let Some(name) = env.ctx.btf.struct_name(target_id)
        {
            let interned = crate::analysis::machine::context::intern_btf_type_name_strict(name);
            state.types.set(
                Reg::R0,
                RegType::PtrToBtfId {
                    type_name: interned,
                    flags: PtrFlags::TRUSTED | PtrFlags::RDONLY,
                    ref_id: None,
                },
            );
        }
    }

    true
}

/// Element-shape distinguisher for `iter_next_fork`. The non-NULL
/// successor's R0 is either a generic memory pointer
/// (`bpf_iter_num_next` returns `int *` into iter state) or a typed
/// BTF pointer (`bpf_iter_task_vma_next` returns `vm_area_struct *`,
/// `bpf_iter_task_next` returns `task_struct *` with the kernel's
/// RCU lifetime).
pub(crate) enum IterNextElemKind {
    AllocMem(u64),
    BtfId {
        type_name: &'static str,
        flags: crate::analysis::machine::reg_types::PtrFlags,
    },
}

/// Fork an `iter_next` call into its two successors. The validator
/// already proved the iter arg points at an Active slot of the
/// proto-declared kind, so `resolve_stack_arg` is expected to succeed
/// here; if the offset went symbolic between validator and applier we
/// drop the path conservatively.
fn iter_next_fork(
    env: &mut VerifierEnv,
    state: State,
    iter_arg: u8,
    kind: IterNextElemKind,
) -> Vec<State> {
    let pc = state.pc;
    // iter_next call sites are force-checkpoint sites
    // (kernel `mark_force_checkpoint` at verifier.c L17523, gated on
    // `is_iter_next_kfunc`). Set the flag lazily on first visit — CFG
    // doesn't have kfunc-name resolution at build time.
    if pc < env.insn_aux_data.len() && !env.replay_mode {
        env.insn_aux_data[pc].force_checkpoint = true;
    }
    let reg = arg_reg(iter_arg);
    let Some((frame, base_off)) = resolve_stack_arg(&state, reg) else {
        return vec![];
    };
    // Record (pc → iter slot) so the back-edge-target prune-defer in
    // `handle_loop_pruning` can find THIS iter_next's iter slot rather
    // than scanning all active iters (which over-defers under nested
    // iters when an unrelated freshly-allocated iter is still at depth<2).
    env.iter_pc_slot.insert(pc, (frame.index(), base_off));

    // Kernel `is_iter_reg_valid_init` (verifier.c v6.15 ~L1135) returns
    // -EPROTO when the iter slot has PTR_UNTRUSTED; `process_iter_arg`
    // surfaces this as "expected an RCU CS when using <kfunc>". Mirrors
    // our `IteratorSlot.untrusted`: if set, reject before forking.
    if matches!(
        state.stack_at(frame).stack_get_iterator(base_off),
        Some(slot) if slot.untrusted
    ) {
        env.fail(crate::analysis::machine::error::VerificationError::InvalidArgType { pc, reg });
        return vec![];
    }

    // Drained-input collapse: a `_next` call on an already-drained
    // iterator returns NULL unconditionally (the kernel just does one
    // `if (it->cnt <= 0) return NULL;` early-out). Don't fork — emit
    // only the null successor, and keep the slot Drained.
    let already_drained = matches!(
        state.stack_at(frame).stack_get_iterator(base_off),
        Some(slot) if matches!(slot.state, IterState::Drained)
    );

    // NULL successor: R0 = scalar 0, slot → Drained.
    let mut null = state.clone();
    if let Some(slot) = null.stack_at(frame).stack_get_iterator(base_off) {
        null.stack_at_mut(frame).stack_set_iterator(
            base_off,
            IteratorSlot {
                state: IterState::Drained,
                ..slot
            },
        );
    }
    null.types.set(Reg::R0, RegType::ScalarValue);
    null.domain.forget(Reg::R0);
    null.domain.assume_ge_imm(Reg::R0, 0);
    null.domain.assume_le_imm(Reg::R0, 0);
    null.set_tnum(Reg::R0, Tnum::constant(0));
    null.clear_scalar_id(Reg::R0);
    clobber_caller_saved(&mut null);
    null.pc = pc + 1;

    if already_drained {
        return vec![null];
    }

    // Non-NULL successor: R0 typed per `kind`, slot stays Active. Bump
    // `iter.depth` (kernel `process_iter_next_call` verifier.c v6.15
    // ~L8919) so successive iterations are distinguishable for the
    // pruning machinery and the inf-loop detector
    // (`iter_active_depths_differ`, ~L18965). Without this the loop top
    // looks identical across iterations and the kernel would mis-fire
    // the infinite-loop check on legitimate iter loops.
    let mut nonnull = state;
    if let Some(slot) = nonnull.stack_at(frame).stack_get_iterator(base_off) {
        nonnull.stack_at_mut(frame).stack_set_iterator(
            base_off,
            IteratorSlot {
                depth: slot.depth.saturating_add(1),
                ..slot
            },
        );
    }
    let r0 = match kind {
        IterNextElemKind::AllocMem(elem_size) => RegType::PtrToAllocMem {
            id: new_ptr_id(),
            mem_size: elem_size,
            ref_id: None,
            dynptr_id: None,
            rdonly: false,
        },
        IterNextElemKind::BtfId { type_name, flags } => RegType::PtrToBtfId {
            type_name,
            flags,
            ref_id: None,
        },
    };
    nonnull.types.set(Reg::R0, r0);
    nonnull.domain.forget(Reg::R0);
    nonnull.set_tnum(Reg::R0, Tnum::unknown());
    nonnull.clear_scalar_id(Reg::R0);
    clobber_caller_saved(&mut nonnull);
    nonnull.pc = pc + 1;

    // Widen imprecise scalars in the queued ACTIVE branch relative to
    // the most recent prior visit at this iter_next call. Kernel
    // `widen_imprecise_scalars` (verifier.c v6.15 ~L8765, called from
    // `process_iter_next_call`) does the same: any imprecise reg or
    // spilled-stack scalar that differs from the parent state's value
    // becomes UNKNOWN. Without this, simple counter-bearing loops like
    // `i++; while(iter_next(...)) {}` produce a fresh distinct state
    // every iteration and the verifier never converges.
    //
    // Skip the just-recorded current state in `explored_states[pc]`:
    // the worklist driver (analysis/mod.rs:362-369) calls `record_state`
    // BEFORE `transfer`, so `prev_states.last()` IS the current state.
    // Comparing cur against itself was a no-op for the entire lifetime
    // of this widener (same bug we hit at the may_goto site). Also skip
    // any prev whose iter slot has a DIFFERENT id from cur's: that's a
    // separate iter_new()/iter_destroy() cycle reusing the same stack
    // slot, and widening across loops would clobber legitimately
    // distinct values (`iter_multiple_sequential_loops`,
    // `iter_search_loop`'s post-drain state). Mirrors the kernel's
    // dfs_depth + same_callsites filter in `find_prev_entry`
    // (verifier.c v6.15 ~L8723).
    // Look up `cur`'s iter slot id and depth (BEFORE this iter_next
    // call — the depth bump in `nonnull` already happened above for
    // the queued state, but `state` cached pre-call holds the pre-bump
    // depth). Only widen against a prev whose:
    //   - iter slot has the same id (same iter loop, not a re-init), AND
    //   - iter slot's depth is exactly cur's pre-bump depth - 1, i.e.
    //     the immediately-prior iter step on this DFS path.
    // Stricter than the kernel's `dfs_depth < cur->dfs_depth`, but
    // we don't track DFS depth; consecutive-iter-depth is the closest
    // proxy and avoids polluting the widener with a state from many
    // iterations back (which can carry stale type info for callee-saved
    // registers that the body reassigns later, e.g. iter_search_loop's
    // `elem = v` capture).
    let (cur_iter_id, cur_iter_depth): (Option<u32>, Option<u32>) = nonnull
        .stack_at(frame)
        .stack_get_iterator(base_off)
        .map(|s| (Some(s.id), Some(s.depth)))
        .unwrap_or((None, None));
    let prev_snapshot: Option<State> = env
        .explored_states
        .get(&pc)
        .and_then(|prev_states| {
            let mut iter = prev_states.iter().rev().filter(|s| s.pc == pc).filter(|s| {
                s.stack_at(frame)
                    .stack_get_iterator(base_off)
                    .map(|slot| {
                        // `cur_iter_depth` is `nonnull`'s post-bump
                        // depth (state.depth + 1). Cached prev states
                        // hold the PRE-call depth (= state.depth at
                        // their iter). Consecutive iter step means
                        // prev.slot.depth + 2 == cur_iter_depth (i.e.
                        // prev was state.depth - 1 the iter before).
                        Some(slot.id) == cur_iter_id
                            && cur_iter_depth.is_some_and(|d| slot.depth + 2 == d)
                    })
                    .unwrap_or(false)
            });
            iter.next()
        })
        .cloned();
    if let Some(prev) = prev_snapshot.as_ref() {
        widen_imprecise_scalars_at_iter_next_call(env, prev, &mut nonnull);
    }

    vec![nonnull, null]
}

/// Widen imprecise scalars in `cur` against `prev` at an iter_next
/// fork. Mirrors kernel `widen_imprecise_scalars` (verifier.c v6.15
/// ~L8765): per-frame scan of regs and spilled-scalar stack slots; any
/// reg/slot not flagged precise whose abstract value disagrees with
/// `prev` collapses to UNKNOWN. Precise entries are left intact (the
/// kernel preserves them via the idmap; we use `precise_regs`).
pub(crate) fn widen_imprecise_scalars_at_iter_next(
    env: &VerifierEnv,
    prev: &State,
    cur: &mut State,
) {
    widen_imprecise_scalars_impl(env, prev, cur, false)
}

/// Same as `widen_imprecise_scalars_at_iter_next` but called at the
/// actual `bpf_iter_*_next` kfunc invocation. Drops the
/// `prev.precise_regs` skip gate: our walker writes precise marks
/// proactively into cached states (kernel marks lazily), so by the
/// time we reach iter_next the cached prev's precise set has
/// future-tense annotations the kernel wouldn't yet have.
/// cb-return / may_goto callers keep the strict gate — those are
/// different convergence regimes where prev-precise really does
/// reflect the live precision contract.
pub(crate) fn widen_imprecise_scalars_at_iter_next_call(
    env: &VerifierEnv,
    prev: &State,
    cur: &mut State,
) {
    widen_imprecise_scalars_impl(env, prev, cur, true)
}

fn widen_imprecise_scalars_impl(
    env: &VerifierEnv,
    prev: &State,
    cur: &mut State,
    at_iter_next_call: bool,
) {
    use crate::analysis::machine::reg::Reg;

    // once the may_goto/iter_next has been visited many
    // times on this path (i.e. we've enumerated a lot of iterations
    // without subsumption firing), drop the precision-skip rule and
    // force-widen even precise scalars. Lets bounded-but-long loops
    // (cond_break1: N=1M) converge despite the loop counter being
    // precision-marked by the access site's `mark_chain_precision`.
    //
    // Threshold tuned to be larger than the small-N enumeration
    // patterns (test1-4: N=1000) so they keep passing via straight
    // enumeration without precision loss. Loops with iteration counts
    // above ~2k were going to time out anyway under the 100k step cap;
    // force-widening lets them converge instead. The loop-head bound
    // check re-narrows the counter on every iteration after widening,
    // so safety is preserved.
    let force_widen_threshold: u32 = 1024;
    let force_widen = cur.may_goto_depth >= force_widen_threshold;

    // Collect changes first; can't mutate while borrowed.
    let mut regs_to_widen: Vec<Reg> = Vec::new();
    for r in [
        Reg::R0,
        Reg::R1,
        Reg::R2,
        Reg::R3,
        Reg::R4,
        Reg::R5,
        Reg::R6,
        Reg::R7,
        Reg::R8,
        Reg::R9,
    ] {
        // Kernel `maybe_widen_reg` (verifier.c v6.15 ~L8752):
        //   if (rold->precise || rcur->precise || regs_exact(...)) return;
        // Skip if EITHER side carries a precision mark — `mark_chain_precision`
        // populates `prev` (cached) precision retroactively when the
        // backward walk lands on a checkpoint, so checking only `cur`
        // would miss the lineage and over-widen.
        //
        // At the actual iter_next kfunc call (`at_iter_next_call=true`),
        // drop the prev.precise_regs gate. Walker writes precise marks
        // proactively to cached states; kernel marks lazily — at iter
        // next time the kernel's rold->precise is typically still
        // false. Other callers (cb-return / may_goto) stay strict.
        let prev_block = !at_iter_next_call && prev.precise_regs.contains(&r);
        // Eviction-resistant precision check: query the env's
        // `precise_pcs` set, which the per-path walker writes at every
        // history step (not just at parent-cache boundaries). Bridges
        // reg-name boundaries via the cached `scalar_ids` map: any
        // reg sharing `r`'s scalar id (in cur or prev) extends the
        // precision check to that aliased reg name as well.
        let aliased_regs: Vec<Reg> = {
            let mut acc: Vec<Reg> = vec![r];
            for ids in [&cur.scalar_ids, &prev.scalar_ids] {
                if let Some(&r_id) = ids.get(&r) {
                    for (&other_r, &id) in ids.iter() {
                        if id == r_id && other_r != r {
                            acc.push(other_r);
                        }
                    }
                }
            }
            acc
        };
        let pc_precise = !at_iter_next_call
            && aliased_regs.iter().any(|&ar| {
                env.precise_pcs.contains(&(prev.pc, ar)) || env.precise_pcs.contains(&(cur.pc, ar))
            });
        if !force_widen && (cur.precise_regs.contains(&r) || prev_block || pc_precise) {
            continue;
        }
        // Only widen scalar-typed regs; pointer types are kept exact
        // (they participate in subsumption via id-loose rules).
        let cur_ty = cur.types.get(r);
        let prev_ty = prev.types.get(r);
        if !matches!(cur_ty, RegType::ScalarValue) || !matches!(prev_ty, RegType::ScalarValue) {
            continue;
        }
        let cur_iv = cur.domain.get_interval(r);
        let prev_iv = prev.domain.get_interval(r);
        let cur_tn = cur.get_tnum(r);
        let prev_tn = prev.get_tnum(r);
        if cur_iv != prev_iv || cur_tn != prev_tn {
            regs_to_widen.push(r);
        }
    }
    for r in regs_to_widen {
        cur.domain.forget(r);
        cur.set_tnum(r, Tnum::unknown());
        cur.clear_scalar_id(r);
        // Once we widen a reg's value, its `precise` mark no longer
        // refers to a meaningful tight bound. Clear so subsumption
        // (which keys on `old.precise_regs`) doesn't demand range_within
        // against a deliberately-coarsened bound.
        if force_widen {
            cur.precise_regs.remove(&r);
        }
    }

    // Spilled scalar slots: walk both frames' stacks. For slots whose
    // abstract value disagrees and isn't precise, widen by joining the
    // current slot's bounds/tnum with the previous explored state's
    // slot rather than fully invalidating. Full invalidation
    // (source_reg=None, bounds=[i64::MIN, i64::MAX]) is too aggressive
    // for loops whose per-iteration scalar is bounded but not constant
    // — downstream MAX_VAR_OFF gates on `ptr += scalar_from_slot`
    // reject the unbounded fill (xdp_synproxy_kern's IHL × 4 spill at
    // r10-128 takes {20, 40} across iterations and gets used as a
    // packet-pointer offset on the next iteration). Union widening
    // gives [20, 40] which the gate accepts.
    use crate::analysis::machine::frame_stack::FrameLevel;
    let n = cur.frames.depth().min(prev.frames.depth());
    for fi in 0..n {
        let level = FrameLevel::from_index(fi);
        let prev_stack_offsets: Vec<i16> = prev.frames.get(level).stack.slot_offsets();
        let mut to_widen: Vec<(i16, crate::analysis::machine::stack_state::SpilledReg)> =
            Vec::new();
        for off in prev_stack_offsets {
            let prev_ty = prev.frames.get(level).stack.get_slot_type(off);
            let cur_ty = cur.frames.get(level).stack.get_slot_type(off);
            if !matches!(prev_ty, RegType::ScalarValue) || !matches!(cur_ty, RegType::ScalarValue) {
                continue;
            }
            let prev_slot = prev.frames.get(level).stack.get_slot(off);
            let cur_slot = cur.frames.get(level).stack.get_slot(off);
            let differs = match (prev_slot, cur_slot) {
                (Some(p), Some(c)) => p.tnum != c.tnum || p.bounds != c.bounds,
                _ => false,
            };
            let cur_precise = cur_slot.map(|s| s.precise).unwrap_or(false);
            let prev_precise = prev_slot.map(|s| s.precise).unwrap_or(false);
            if differs
                && (force_widen || (!cur_precise && !prev_precise))
                && let Some(p) = prev_slot
            {
                to_widen.push((off, p.clone()));
            }
        }
        let cur_stack = &mut cur.frames.get_mut(level).stack;
        for (off, prev_slot) in to_widen {
            cur_stack.widen_slot(off, &prev_slot);
        }
    }
}

fn clobber_caller_saved(state: &mut State) {
    for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
        state.types.set(r, RegType::NotInit);
        state.domain.forget(r);
        state.set_tnum(r, Tnum::unknown());
        state.clear_scalar_id(r);
    }
}

/// What trust level a kfunc demands of its pointer args.
/// `Trusted` = `KF_TRUSTED_ARGS` (must be PTR_TRUSTED or refcounted).
/// `Rcu` = `KF_RCU` (allows PTR_TRUSTED, PTR_RCU, or refcounted).
#[derive(Copy, Clone)]
enum TrustBand {
    Trusted,
    Rcu,
}

/// True iff `actual` (a pointer-typed reg) satisfies `band`. Used by
/// the kfunc dispatcher's `KF_TRUSTED_ARGS` / `KF_RCU` enforcement.
///
/// "Refcounted" pointers (acquire-tracked specializations:
/// `PtrToTask`, `PtrToCgroup`, `PtrToCpumask`, `PtrToOwnedKptr`,
/// `PtrToArena`, `PtrToSocket{,Common}`, `PtrToTcpSock`,
/// `PtrToMapKptr` with the kernel's `MEM_ALLOC` flag) carry an
/// acquire-tracked ref_id; the kernel treats them as trusted for
/// kfunc-arg purposes regardless of explicit `PtrFlags`. Generic
/// `PtrToBtfId` consults `PtrFlags` directly. `PtrToAllocMem` is
/// neither trusted nor RCU — it represents iter-element memory that
/// `KF_TRUSTED_ARGS` consumers must reject (closes
/// `iter_next_ptr_mem_not_trusted`).
fn pointer_arg_meets_trust(actual: &RegType, band: TrustBand) -> bool {
    use crate::analysis::machine::reg_types::PtrFlags;

    let flags = actual.ptr_flags();
    let has_trusted = flags.contains(PtrFlags::TRUSTED);
    let has_rcu = flags.contains(PtrFlags::RCU);
    let has_untrusted = flags.contains(PtrFlags::UNTRUSTED);

    // Acquire-tracked specializations are trusted-by-construction
    // (the kernel mints them through KF_ACQUIRE-flagged paths and
    // ref-tracks them). Their reg variants don't carry PtrFlags, so
    // detect via `get_ref_id().is_some()` plus a positive shape match.
    let is_acquire_tracked = matches!(
        actual,
        RegType::PtrToTask { ref_id: Some(_) }
            | RegType::PtrToCgroup { ref_id: Some(_) }
            | RegType::PtrToCpumask { ref_id: Some(_) }
            | RegType::PtrToOwnedKptr {
                ref_id: Some(_),
                ..
            }
            | RegType::PtrToArena {
                ref_id: Some(_),
                ..
            }
            | RegType::PtrToSocket { ref_id: Some(_) }
            | RegType::PtrToSockCommon { ref_id: Some(_) }
            | RegType::PtrToTcpSock { id: Some(_) }
    );

    match band {
        TrustBand::Trusted => (has_trusted && !has_untrusted) || is_acquire_tracked,
        TrustBand::Rcu => (has_trusted || has_rcu) && !has_untrusted || is_acquire_tracked,
    }
}

/// `bpf_throw(cookie)`: terminates execution on this path. The kernel
/// runs the program-default exception callback (if registered) or
/// unwinds out of the program returning 0 — either way, the site has
/// no in-program successor and we drop the path.
///
/// Reference cleanup is the caller's responsibility: a live
/// `bpf_obj_new` / `bpf_refcount_acquire` reference at a throw site is
/// rejected with "Unreleased reference" because no handler is empowered
/// to release it on the unwind path. This matches the kernel's
/// `check_reference_leak` invocation at every throw.
fn throw(env: &mut VerifierEnv, state: State) -> Vec<State> {
    // Kernel: `bpf_throw` is forbidden inside any callback subprog
    // entered via bpf_loop / bpf_for_each_map_elem / bpf_timer_set_callback
    // / bpf_user_ringbuf_drain / bpf_find_vma. (The dedicated
    // `__exception_cb` pass in `analyze_exception_cb` is allowed to throw
    // — its frames don't carry `is_callback`.) Mirrors the kernel
    // rejection "cannot be called from callback subprog".
    if !env.analyzing_exception_cb && state.frames.iter().any(|f| f.is_callback()) {
        env.fail(VerificationError::ExceptionCallbackInvalid {
            reason: "cannot be called from callback subprog".to_string(),
        });
        return vec![];
    }
    // Kernel: "function calls are not allowed while holding a lock".
    // bpf_throw under an active spin_lock would unwind without releasing
    // the lock — the kernel rejects up-front.
    // (See `exceptions_fail::reject_with_lock` and `reject_subprog_with_lock`.)
    if state.has_active_lock() {
        env.fail(VerificationError::InvalidArgType {
            pc: state.pc,
            reg: Reg::R0,
        });
        return vec![];
    }
    // Kernel: bpf_throw inside an RCU read-side critical section is
    // also rejected — the unwind path doesn't run rcu_read_unlock, so
    // the program would leak the RCU lock. Mirrors
    // `exceptions_fail::reject_with_rcu_read_lock` (kernel msg
    // "function calls are not allowed while holding a lock" — same
    // family, RCU bucket).
    if state.in_rcu_read_section() {
        env.fail(VerificationError::InvalidArgType {
            pc: state.pc,
            reg: Reg::R0,
        });
        return vec![];
    }
    if state.has_unreleased_refs() {
        env.fail(VerificationError::UnreleasedReference);
    }
    // When no exception_cb is registered (load-time decl-tag or runtime
    // bpf_set_exception_callback), the kernel's default unwind returns
    // the throw cookie as the program's R0 — so R1 at the throw site
    // must satisfy whatever return-value rule applies at the program's
    // main exit. fentry/fexit demands R0 == 0; we mirror that here for
    // R1, matching the kernel's "register R1 has smin=N smax=N" message.
    let no_handler =
        env.ctx.exception_callback.is_none() && state.effective_exception_cb().is_none();
    if no_handler && tracing_requires_zero_retval(env.ctx) {
        let (lo, hi) = state.domain.get_interval(Reg::R1);
        if lo != 0 || hi != 0 {
            env.fail(VerificationError::InvalidReturnCode { pc: state.pc });
            return vec![];
        }
    }
    vec![]
}

/// True when the SEC indicates an fentry/fexit attach. The kernel's
/// `check_return_code` enforces R0 == 0 at exit for both flavors; we
/// mirror that at exception cb exits and (for the no-handler case)
/// throw cookies. Driven off `attach_flavor` alone — the SEC suffices
/// to identify these attach types and `prog_kind` may legitimately
/// resolve to `Unknown` for `?fentry/...` test SECs without
/// invalidating the constraint.
fn tracing_requires_zero_retval(ctx: &crate::analysis::machine::context::ExecContext) -> bool {
    matches!(ctx.attach_flavor.as_deref(), Some("fentry") | Some("fexit"))
}

/// Callback-fork for `bpf_wq_set_callback_impl(wq, cb, flags__ign, aux__ign)`.
///
/// The cb runs asynchronously when the workqueue fires, so registration
/// must occur with no held spin lock and no unreleased refs (mirrors
/// `BPF_TIMER_SET_CALLBACK`'s constraint). The cb signature is
/// `int (*cb)(void *map, int *key, void *value)` — the kernel installs
/// R1=CONST_PTR_TO_MAP, R2=PTR_TO_MAP_KEY, R3=PTR_TO_MAP_VALUE off the
/// wq's owning map (caller's R1 is `&map_value->wq` whose `map_idx`
/// identifies the owning map). We don't track PTR_TO_MAP_KEY distinctly;
/// approximate as the lax `PtrToBtfId{type_name:"unknown",TRUSTED}`
/// (matches the timer-cb fallback). On the cb's Exit `transfer_exit`
/// drops the path; only the skip path carries post-call state forward.
fn transfer_kfunc_wq_set_callback(
    env: &mut VerifierEnv,
    in_types: &crate::analysis::machine::reg_types::TypeState,
    state: State,
    btf_id: u32,
    proto: &CallProto,
) -> Vec<State> {
    let pc = state.pc;

    // R2 must be PtrToCallback — the proto's PtrToCallback validator
    // already accepted; pull subprog target.
    let RegType::PtrToCallback { subprog_pc } = in_types.get(Reg::R2) else {
        env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R2 });
        return vec![];
    };
    let cb_entry = subprog_pc as usize;

    // Async-cb constraint: registration cannot happen while a spin lock
    // is held or refs are outstanding — kernel rejects the same way it
    // does for `bpf_timer_set_callback`.
    if state.has_active_lock() || state.has_unreleased_refs() {
        env.fail(VerificationError::InvalidArgType { pc, reg: Reg::R2 });
        return vec![];
    }

    // Successor A: skip path. Apply proto-driven R0 (Scalar return),
    // clobber caller-saved.
    let mut skip_state = state.clone();
    apply_call_proto_r0(in_types, &mut skip_state, proto, env.ctx.prog_kind);
    for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
        skip_state.types.set(r, RegType::NotInit);
        skip_state.domain.forget(r);
        skip_state.set_tnum(r, Tnum::unknown());
        skip_state.clear_scalar_id(r);
    }
    skip_state.pc = pc + 1;

    // Successor B: enter the cb with a fresh frame. Bail with the skip
    // state alone if we're at max call depth.
    if state.num_frames() >= 8 {
        return vec![skip_state];
    }

    // Pull caller's R1 (wq) `map_idx` for cb-arg typing.
    let wq_map_idx = match in_types.get(Reg::R1) {
        RegType::PtrToMapValue { map_idx, .. } => Some(map_idx),
        _ => None,
    };

    let mut cb_state = state;
    let caller_level_idx = cb_state.current_frame_level();
    let caller_stack_snapshot = cb_state.frames.get(caller_level_idx).stack.clone();
    // `helper` field on the frame is helper-id-keyed (see
    // `apply_return_bounds_for_cb_helper`); kfunc cbs have no real
    // helper id. Pass 0 — the consumer falls back to a generic Scalar
    // R0, which matches what the proto already emits for skip_state.
    // Async cbs drop on Exit anyway, so this only matters if a future
    // path threads cb-Exit back to caller.
    let _ = btf_id;
    cb_state.push_callback_frame(pc + 1, 0);
    cb_state.frames.current_mut().set_cb_propagation(
        caller_stack_snapshot,
        caller_level_idx.index(),
        /* widen */ false, // async, kernel doesn't iterate; concrete merge
    );

    crate::analysis::transfer::types::update_call_rel_types(&mut cb_state);
    cb_state.domain.clear_packet_size_bounds();

    for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
        cb_state.types.set(r, RegType::NotInit);
        cb_state.domain.forget(r);
        cb_state.set_tnum(r, Tnum::unknown());
        cb_state.clear_scalar_id(r);
    }

    use crate::analysis::machine::reg_types::PtrFlags;
    let unknown_btf = || RegType::PtrToBtfId {
        type_name: "unknown",
        flags: PtrFlags::TRUSTED,
        ref_id: None,
    };
    // R1 = CONST_PTR_TO_MAP (the wq's owning map).
    let r1_ty = match wq_map_idx {
        Some(map_idx) => RegType::PtrToMapObject { map_idx },
        None => unknown_btf(),
    };
    cb_state.types.set(Reg::R1, r1_ty);
    cb_state.domain.forget(Reg::R1);
    cb_state.set_tnum(Reg::R1, Tnum::unknown());
    cb_state.clear_scalar_id(Reg::R1);
    // R2 = key (PTR_TO_MAP_KEY in kernel; approximate as lax BtfId).
    cb_state.types.set(Reg::R2, unknown_btf());
    cb_state.domain.forget(Reg::R2);
    cb_state.set_tnum(Reg::R2, Tnum::unknown());
    cb_state.clear_scalar_id(Reg::R2);
    // R3 = value (PTR_TO_MAP_VALUE off the owning map).
    let r3_ty = match wq_map_idx {
        Some(map_idx) => RegType::PtrToMapValue {
            id: new_ptr_id(),
            offset: Some(0),
            map_idx,
            map_uid: None,
            rdonly: false,
        },
        None => unknown_btf(),
    };
    cb_state.types.set(Reg::R3, r3_ty);
    cb_state.domain.forget(Reg::R3);
    if wq_map_idx.is_some() {
        cb_state.domain.init_map_value_ptr(Reg::R3);
    }
    cb_state.set_tnum(Reg::R3, Tnum::unknown());
    cb_state.clear_scalar_id(Reg::R3);

    cb_state.pc = cb_entry;

    vec![skip_state, cb_state]
}
