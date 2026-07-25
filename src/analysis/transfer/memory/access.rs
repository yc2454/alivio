// src/analysis/transfer/memory/access.rs

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::error::VerificationError;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use crate::common::constants;
use crate::common::ctx_model;
use crate::common::mem_region_model;
use RegType::*;
use log::{error, info};

use super::map::{check_kptr_field_access, check_map_access};
use super::packet::{check_packet_access, check_packet_meta_access};
use super::stack::check_stack_access;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
    HelperBuffer,
    HelperPrimitive,
}

/// True iff `base` has a variable (non-fixed) offset relative to its
/// underlying anchor — i.e. some scalar was added to it whose exact value
/// is not statically known. We look at the interval domain's `ptr_off` and
/// check `var_off > 0`. Variable-offset accesses are the
/// canonical precision sinks for kernel `mark_chain_precision`.
fn base_has_variable_offset(state: &State, base: Reg) -> bool {
    use crate::domains::numeric::NumericDomain;
    let NumericDomain::Interval(ref ivl) = state.domain else {
        return false;
    };
    ivl.get_ptr_offset(base)
        .map(|p| p.var_off > 0)
        .unwrap_or(false)
}

/// Validates memory load safety.
pub fn check_load(env: &mut VerifierEnv, state: &State, base: Reg, size: i64, off: i16) {
    let ctx = env.ctx;
    let base_type = state.types.get(base);
    let pc = state.pc;

    // every memory access is a precision sink. Walk the
    // History backward marking the access's offset lineage precise on
    // every cached state on the path. Mirrors kernel
    // `mark_chain_precision` (verifier.c v6.15 ~L4500-4900). The walker
    // traces Alu/Mov/Load/Call chains starting from `base` (the access
    // pointer) and updates frontier across them; if the access has a
    // recorded variable-offset contributor (`ptr += Reg(scalar)`), we
    // start from the scalar instead — saves the walker some work but
    // reaches the same lineage either way.
    //
    // Skip R10 — the frame pointer is never re-assigned, so walking
    // from it is a no-op that just marks R10 precise on history's worth
    // of cached states (wasted work, no behavior change).
    // Mark precise ONLY the scalar that supplied the access's variable
    // offset (`ptr += Reg(scalar)`), never the bare pointer base. The
    // kernel's `mark_chain_precision` is scalar-only: a pointer
    // dereference marks the scalar offset contributor precise (for the
    // bounds check), not the pointer register itself — marking the base
    // would propagate (via `propagate_precision`) to scalar incarnations
    // of that register downstream and block subsumption. `check_store`
    // (below) marks contributor-only the same way.
    if let Some(hidx) = state.history_idx
        && base != Reg::R10
        && let Some(&sink) = state.var_off_contributor.get(&base)
    {
        crate::analysis::flow::precision::mark_chain_precision_backward(
            env,
            hidx,
            state.parent_cache_id,
            sink,
        );
    }
    let _ = base_has_variable_offset;

    match base_type {
        PtrToStack { frame_level } => {
            let offset = state.domain.get_distance_fixed(base, Reg::R10);
            check_stack_access(
                env,
                state,
                base,
                offset,
                off as i64,
                size,
                pc,
                AccessKind::Read,
                None,
                frame_level,
            );
        }
        PtrToPacket => {
            check_packet_access(env, state, base, off, size, pc, AccessKind::Read);
        }
        PtrToCtx => {
            if !ctx_model::is_valid_ctx_read(env, off, size) {
                error!(
                    "Unsafe ctx load at pc {}: offset {} is not readable",
                    pc, off
                );
                env.fail(VerificationError::UnsafeCtxAccess { pc, off, size });
            }
        }
        PtrToMapValue {
            id: _,
            offset: map_off_opt,
            map_idx,
            ..
        } => {
            if let Some(map_def) = ctx.map_defs.get(map_idx) {
                if map_def.map_flags & constants::BPF_F_WRONLY_PROG != 0 {
                    error!("Map load is forbidden!");
                    env.fail(VerificationError::MapLoadForbidden { pc, map_idx });
                }
                check_kptr_field_access(
                    env,
                    state,
                    map_def,
                    map_idx,
                    base,
                    map_off_opt,
                    off,
                    size,
                    pc,
                    /*is_store=*/ false,
                );
                let map_limit = map_def.value_size as i64;
                check_map_access(
                    env,
                    state,
                    map_limit,
                    map_off_opt,
                    map_idx,
                    base,
                    map_def,
                    off,
                    size,
                    pc,
                );
            } else {
                error!("Map not found!");
                env.fail(VerificationError::MapNotFound { pc, map_idx })
            }
        }
        PtrToMapValueOrNull { map_idx, .. } => {
            // Loads through a nullable map pointer are unconditionally
            // rejected by the kernel — the user must null-check first
            // (which promotes the type to PtrToMapValue). Without this,
            // pruning that loses an unrefined nullable arrival lets
            // subsequent loads slip through (cluster: regsafe).
            error!(
                "Load through PtrToMapValueOrNull at pc {}: requires null check",
                pc
            );
            let _ = off;
            let _ = size;
            let _ = map_idx;
            env.fail(VerificationError::UnsafeMapLoad {
                pc,
                off: off as i64,
                size,
                limit: 0,
            });
        }
        PtrToTcpSock { .. } | PtrToSockCommon { .. } | PtrToSocket { .. } => {
            if !mem_region_model::is_valid_mem_region_read(state.types.get(base), off, size) {
                error!(
                    "Invalid socket access at pc {}: {:?} offset {} size {}",
                    pc, base_type, off, size
                );
                env.fail(VerificationError::UnsafeSocketAccess { pc, off, size });
            }
        }
        PtrToSocketOrNull { .. } | PtrToSockCommonOrNull { .. } | PtrToTcpSockOrNull { .. } => {
            error!(
                "Load from nullable socket at pc {}: base {:?}+{} requires null check",
                pc, base, off
            );
            env.fail(VerificationError::UnsafeGenericLoad {
                pc,
                base,
                off,
                base_type,
            });
        }
        PtrToPacketMeta => {
            check_packet_meta_access(env, state, base, off, size, pc);
        }
        PtrToBtfId { .. } | PtrToMapObject { .. } => {
            // Reject direct deref of `__user` / `__percpu` BTF type-tag
            // pointers. Kernel propagates these tags from the attach
            // target's vmlinux/module BTF to R1..Rn at load time; the
            // verifier rejects the load via `btf_struct_access` →
            // -EACCES. Programs must use bpf_copy_from_user /
            // bpf_per_cpu_ptr first.
            //
            // Closes btf_type_tag_user.c::test_user1, test_sys_getsockname,
            // and btf_type_tag_percpu.c::test_percpu1 (via the
            // ATTACH_TARGET_ARG_TAGS table in runner.rs, consulted in
            // ctx_model.rs's lax fallback for fentry/LSM/tp_btf).
            use crate::analysis::machine::reg_types::PtrFlags;
            let tags = base_type.ptr_flags();
            if tags.contains(PtrFlags::USER) || tags.contains(PtrFlags::PERCPU) {
                error!(
                    "Direct deref of __user/__percpu PtrToBtfId at pc {}: {:?}",
                    pc, base_type
                );
                env.fail(VerificationError::UnsafeGenericLoad {
                    pc,
                    base,
                    off,
                    base_type,
                });
                return;
            }
            // Skip the field-table check for any PtrToBtfId whose
            // concrete kernel type isn't modeled in `mem_region_model`
            // (e.g. `struct socket`, `struct task_struct`, `struct
            // linux_binprm` for LSM hooks). The kernel relies on BTF for
            // these and accepts any valid BTF field offset; without a
            // BTF-driven check our hand table would over-reject the LSM
            // / tp_btf corpus. PtrToMapObject and the modeled
            // PtrToBtfId types (`bpf_iter_meta`) still go through the
            // table.
            let has_field_table = matches!(
                base_type,
                PtrToBtfId {
                    type_name: "bpf_iter_meta",
                    ..
                } | PtrToMapObject { .. }
            );
            if has_field_table
                && !mem_region_model::is_valid_mem_region_read(state.types.get(base), off, size)
            {
                error!(
                    "Invalid socket access at pc {}: {:?} offset {} size {}",
                    pc, base_type, off, size
                );
                env.fail(VerificationError::UnsafeSocketAccess { pc, off, size });
            }
        }
        PtrToAllocMem { mem_size, .. } => {
            // Bounded allocated memory (: surfaced when
            // bpf_dynptr_slice's PtrToAllocMemOrNull return is
            // refined to PtrToAllocMem after a null check). Mirrors
            // the store-side bounds check at access.rs:269.
            let access_end = off as i64 + size;
            if off < 0 || access_end > mem_size as i64 {
                error!(
                    "Unsafe memory load at pc {}: base {:?}+{} size {} exceeds allocated memory size {}",
                    pc, base, off, size, mem_size
                );
                env.fail(VerificationError::UnsafeMemoryLoad {
                    pc,
                    base,
                    off,
                    size,
                });
            }
        }
        PtrToArena { .. } => {
            // Arena memory is sparse-mapped and lazily faulted: accesses
            // outside the alloc'd page run zero-faults rather than reject.
            // The kernel verifier therefore doesn't bounds-check arena
            // loads against the alloc's `mem_size`, only against the
            // arena's overall 4GB virtual range (modeled implicitly by
            // the addr-space cast, which we don't trace). See
            // `verifier_arena.c::basic_alloc2` (writes `page1 + 2*PAGE_SIZE`
            // through a 2-page alloc) and `verifier_arena_large.c::big_alloc1`
            // (`page2 +/- PAGE_SIZE`). Accept any offset; loaded value
            // stays `ScalarValue` via the type-update path.
        }
        // lax field-access on trusted typed BTF
        // pointers we don't have a `mem_region_model` entry for.
        // Mirrors the `PtrToBtfId{type_name: "unknown"}`
        // policy — accept any field read; result is `ScalarValue` (or a
        // nested PtrToBtfId if narrower modeling lands later).
        PtrToTask { .. } | PtrToCgroup { .. } => {
            // accept; loaded value left as `ScalarValue` by the
            // type-update path (or PtrToBtfId for allowlisted
            // pointer fields via trusted_field_load).
        }
        PtrToOwnedKptr { .. } => {
            // Field deref through a graph-kptr (bpf_obj_new'd struct,
            // or pop result from bpf_list/rbtree). The kernel admits
            // these via `mark_btf_ld_reg` / `btf_struct_access` using
            // the kptr's `pointee_btf_id`; container_of patterns
            // (`f = container_of(node, struct foo, node); v = f->data`)
            // surface as negative-offset loads relative to the kptr
            // base — kernel admits because the kptr's allocated region
            // is the parent struct. Accept any aligned read; loaded
            // value left as `ScalarValue` by the type-update path.
            // Mirrors PtrToBtfId's lax admit for layout-known names
            // not in `mem_region_model`.
        }
        PtrToMapKptr {
            pointee_btf_id,
            offset: reg_off,
            ..
        } => {
            // Field deref through a kptr loaded from a map's `__kptr*`
            // field. Kernel admits these via `btf_struct_access` using
            // the kptr's pointee BTF (mark_btf_ld_reg attenuates the
            // result's flags to UNTRUSTED on Unref / RCU on Ref under
            // implicit RCU CS / TRUSTED on post-xchg). The downstream
            // `bpf_per_cpu_ptr` / `bpf_this_cpu_ptr` arg validator
            // (transfer.rs:190) still gates the PERCPU-only fail tests
            // (`marked_as_untrusted_or_null`,
            // `inherit_untrusted_on_walk`,
            // `mark_ref_as_untrusted_or_null`), so widening the deref
            // here doesn't unmask those rejections — they fire one
            // call later. Loaded value left as `ScalarValue`.
            //
            // Bounds check via the pointee struct's BTF size: kernel
            // `btf_struct_access` rejects "access beyond struct <name>
            // at off N size M" for off+size > sizeof(struct). Closes
            // map_kptr_fail::correct_btf_id_check_size where the
            // program reads `*(int *)((void *)p + sizeof(*p))` —
            // exactly one int past the struct end. Off and size from
            // caller are i16/i64 of the load instruction; we only
            // enforce when the pointee BTF id resolves to a known
            // size (>0).
            // Effective offset into the pointee struct = reg.offset
            // (carried from prior `R = R + K` ALU) plus the
            // load insn's immediate `off`. Programs use the
            // `R += sizeof_field; R = *(T *)(R - sizeof_field)` idiom
            // (jit_probe_mem.c) to test JIT probe-mem path; the deref is at
            // effective offset 0 even though insn `off` is negative.
            let pointee_size = ctx.btf.type_size_bytes(pointee_btf_id);
            let eff_off = (off as i64).saturating_add(reg_off as i64);
            if pointee_size > 0
                && (eff_off < 0 || eff_off.saturating_add(size) > pointee_size as i64)
            {
                let name = ctx
                    .btf
                    .struct_name(pointee_btf_id)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("btf_id_{pointee_btf_id}"));
                error!(
                    "[Verifier] pc {}: access beyond struct {} at off {} size {}",
                    pc, name, eff_off, size
                );
                env.fail(VerificationError::UnsafeGenericLoad {
                    pc,
                    base,
                    off,
                    base_type,
                });
            }
        }
        ScalarValue | NotInit => {
            // Base-verifier mode (no BCF round-trip): `state.bcf` is None,
            // so there is no bundle and no kernel oracle to re-check a
            // dropped path. zovia IS the verifier here, so a load via a
            // scalar / uninitialized base is a hard reject — exactly as the
            // kernel's `check_mem_access` rejects "R%d invalid mem access".
            // Without this, the unprovable-path DROP below (which exists
            // only to keep DFS alive under BCF, where the kernel catches a
            // truly-reachable site via canonical-hash MISS) silently turns
            // every use-after-release / use-after-free / invalidated-pointer
            // deref into a soundness FALSE_ACCEPT
            // (verifier_ref_tracking::*_after_release, dynptr slice
            // use-after-release, test_sk_lookup_kern::err_use_after_free, …).
            // Mirrors the already-correct gating in `check_reg_readable`
            // (common.rs) and `try_discharge_helper_arg_reject`, which both
            // fall through to `fail` when the BCF emit is inert.
            if state.bcf.is_none() {
                error!(
                    "[Verifier] pc {}: invalid mem access via scalar/uninit base {:?}+{} size {}",
                    pc, base, off, size
                );
                env.fail(VerificationError::UnsafeGenericLoad {
                    pc,
                    base,
                    off,
                    base_type,
                });
                return;
            }
            // The single-pass userspace-BCF kernel is a bundle proof
            // CHECKER only: no in-kernel prover, no solver, and — unlike
            // two-pass BCF's set6 `detect_conflict_eq`, which is NOT
            // applied to the built kernel — no trusted syntactic
            // dead-path rule. On this invalid scalar load it computes
            // the path_cond's canonical hash and looks it up in the
            // precomputed bundle; a `kind=UNREACHABLE` entry discharges
            // it (`bcf_take_discharge` → `PROCESS_BPF_EXIT`). So a
            // syntactically-dead path still needs a *checkable* bundle
            // entry: a silent structural drop emits no entry, so the
            // kernel hashes the path, misses the bundle, and -EACCES.
            // Mirror the checker faithfully — prove the accumulated
            // path_cond unsat via the solver and emit a
            // `kind=UNREACHABLE` bundle entry; drop the path only on a
            // successful, checkable proof.
            if crate::refinement::emit::try_emit_path_unreachable_entry(env, state) {
                info!(
                    target: "app",
                    "[bcf] reactive path-unreachable: discharged generic-load reject at pc {} (cvc5 proof, kind=UNREACHABLE)",
                    pc
                );
                // (children_unsafe marking happens inside
                // try_emit_path_unreachable_entry, mirroring the
                // kernel where bcf_refine itself marks parents[].)
                env.bcf_path_unreachable = true;
                return;
            }
            // On cvc5-can't-prove, drop THIS path instead of halting
            // whole-section analysis. Rationale: zovia's interval-only
            // kernel-mode can produce spurious unreachable paths
            // (same-predicate correlation lost in the interval domain),
            // and halting blocks DFS from exploring other branches that
            // DO reach the target reject via shorter trajectories.
            // End-to-end safety preserved: the kernel (and selftest's
            // `--kernel-mode` checker) remains the ultimate soundness
            // gate — a genuinely reachable unsafe load is still rejected
            // at load via canonical-hash MISS.
            log::warn!(
                target: "app",
                "[bcf] dropping unprovable unsafe-load path at pc {} (base {:?}+{}, Type: {:?}) — DFS continues",
                pc, base, off, base_type
            );
            env.bcf_path_unreachable = true;
        }
        _ => {
            error!(
                "Non-stack, non-ctx load at pc {} from base {:?}+{}",
                pc, base, off
            );
            env.fail(VerificationError::UnsafeGenericLoad {
                pc,
                base,
                off,
                base_type,
            });
        }
    }
}

/// Validates memory store safety.
pub fn check_store(
    env: &mut VerifierEnv,
    state: &State,
    base: Reg,
    size: i64,
    off: i16,
    src_type: RegType,
) {
    let ctx = env.ctx;
    let base_ty = state.types.get(base);
    let pc = state.pc;

    // variable-offset store is also a precision sink.
    // precision-mark the variable-offset contributor.
    //
    // When `base` was constructed via `Alu Add base, Reg(scalar)` in
    // `arithmetic::handle_add`, the scalar that supplied the variable
    // offset was recorded in `state.var_off_contributor[base]`. At the
    // access (a precision sink), we walk the History backward from this
    // step, marking the scalar's transitive lineage precise on every
    // cached state on the path. This is what lets the kernel-aligned
    // wideners at iter_next / may_goto / cb-return preserve the offset
    // reg's bound across widening sites — without it, the widener
    // clobbers the offset to UNKNOWN and the next iteration's bounds
    // check fails.
    //
    // Mirrors kernel `mark_chain_precision` (verifier.c v6.15
    // ~L4500-4900): kernel walks back from precision sinks and marks
    // ancestors precise via id-link / ALU-source chasing. We use the
    // explicit contributor map plus the AST-walk in
    // `mark_chain_precision_backward` (env.rs) as the same chain.
    if let Some(hidx) = state.history_idx
        && let Some(&offset_reg) = state.var_off_contributor.get(&base)
    {
        crate::analysis::flow::precision::mark_chain_precision_backward(
            env,
            hidx,
            state.parent_cache_id,
            offset_reg,
        );
    }
    let _ = base_has_variable_offset;

    match base_ty {
        PtrToMapValue {
            id: _,
            offset: map_off,
            map_idx,
            rdonly,
            ..
        } => {
            if rdonly {
                // PTR_TO_MAP_KEY-style read-only marker (set on R2 of
                // bpf_for_each_map_elem callbacks). Kernel: "write to
                // map_key forbidden". Closes
                // for_each_map_elem_write_key::test_map_key_write.
                error!(
                    "[Verifier] pc {}: write into rdonly map_key at off {} size {}",
                    pc, off, size
                );
                env.fail(VerificationError::MapStoreForbidden { pc, map_idx });
                return;
            }
            if let Some(map_def) = ctx.map_defs.get(map_idx) {
                if map_def.map_flags & constants::BPF_F_RDONLY_PROG != 0 {
                    error!("Map store is forbidden!");
                    env.fail(VerificationError::MapStoreForbidden { pc, map_idx });
                }
                check_kptr_field_access(
                    env, state, map_def, map_idx, base, map_off, off, size, pc,
                    /*is_store=*/ true,
                );
                let map_limit = map_def.value_size as i64;
                check_map_access(
                    env, state, map_limit, map_off, map_idx, base, map_def, off, size, pc,
                );
            } else {
                error!("Map not found!");
                env.fail(VerificationError::MapNotFound { pc, map_idx })
            }
        }
        PtrToStack { frame_level } => {
            let offset = state.domain.get_distance_fixed(base, Reg::R10);
            check_stack_access(
                env,
                state,
                base,
                offset,
                off as i64,
                size,
                pc,
                AccessKind::Write,
                Some(src_type),
                frame_level,
            );
        }
        PtrToPacket => {
            check_packet_access(env, state, base, off, size, pc, AccessKind::Write);
        }
        PtrToPacketMeta => {
            check_packet_meta_access(env, state, base, off, size, pc);
        }
        PtrToMapValueOrNull { map_idx, .. } => {
            error!("Unsafe nullable map store at pc {}", pc);
            env.fail(VerificationError::UnsafeMapStore {
                pc,
                off: off as i64,
                size,
                limit: env.ctx.map_defs.get(map_idx).unwrap().value_size as i64,
            });
        }
        PtrToCtx => {
            if !ctx_model::is_valid_ctx_write(env, off, size) {
                error!(
                    "Unsafe ctx store at pc {}: offset {} is not writable",
                    pc, off
                );
                env.fail(VerificationError::UnsafeCtxAccess { pc, off, size });
            }
        }
        PtrToSocket { .. } | PtrToSockCommon { .. } | PtrToTcpSock { .. } => {
            error!("Cannot write to socket struct at pc {}", pc);
            env.fail(VerificationError::UnsafeGenericStore {
                pc,
                base,
                off,
                base_type: base_ty,
            });
        }
        PtrToSocketOrNull { .. } | PtrToSockCommonOrNull { .. } | PtrToTcpSockOrNull { .. } => {
            error!("Cannot write to nullable socket at pc {}", pc);
            env.fail(VerificationError::UnsafeGenericStore {
                pc,
                base,
                off,
                base_type: base_ty,
            });
        }
        PtrToAllocMem {
            mem_size, rdonly, ..
        } => {
            // `bpf_dynptr_slice` returns `const void *` — kernel rejects
            // any store through it with "cannot write into rdonly_mem".
            // The rdonly bit is stamped on the slice result by
            // `RetKind::PtrToAllocMemFromArgRdonly` and survives null-check
            // refinement; `bpf_dynptr_slice_rdwr` keeps `rdonly: false`.
            if rdonly {
                error!(
                    "Unsafe memory store at pc {}: base {:?}+{} size {} writes into rdonly_mem",
                    pc, base, off, size
                );
                env.fail(VerificationError::UnsafeMemoryStore {
                    pc,
                    base,
                    off,
                    size,
                });
                return;
            }
            let access_end = off as i64 + size;
            if access_end > mem_size as i64 {
                error!(
                    "Unsafe memory store at pc {}: base {:?}+{} size {} exceeds allocated memory size {}",
                    pc, base, off, size, mem_size
                );
                env.fail(VerificationError::UnsafeMemoryStore {
                    pc,
                    base,
                    off,
                    size,
                });
            }
        }
        PtrToOwnedKptr { .. } => {
            // Stores into a freshly-allocated owned kptr (`m->key = 2`
            // after `bpf_obj_new` / `bpf_refcount_acquire`) are allowed
            // by kernel `verifier.c` v6.15 — `check_ptr_to_btf_access`
            // for `MEM_ALLOC` falls through to BTF field-typed access,
            // which we don't model precisely. Accept permissively here:
            // the alternative is rejecting kernel-accepting programs.
            // Bounds against the allocated object size are not tracked
            // (`PtrToOwnedKptr` doesn't carry a size); future precision
            // can attach the BTF id of the underlying type and bound
            // against it.
        }
        PtrToArena { .. } => {
            // Symmetric with the load side: arena memory is sparse-mapped,
            // so OOB-looking stores zero-fault rather than reject. The
            // kernel verifier doesn't bound stores against alloc size.
        }
        // writes through a BTF-typed pointer.
        // Mirror the load-side policy at access.rs::update_load_types:
        //   * `type_name == "unknown"` (no layout) — accept; the BTF
        //     resolver intentionally widens to "unknown" for kernel
        //     structs we don't have mem_region_model entries for, and
        //     struct_ops methods commonly write to embedded state
        //     (e.g. `bictcp` inside `struct sock`).
        //   * named struct with a layout — bounds-check via
        //     mem_region_model. Future work: extend mem_region_model with
        //     entries for named kernel structs and tighten this arm.
        PtrToBtfId { .. } => {
            use crate::analysis::machine::reg_types::PtrFlags;
            let is_unknown = matches!(
                base_ty,
                PtrToBtfId {
                    type_name: "unknown",
                    ..
                }
            );
            // MEM_ALLOC: `PTR_TO_BTF_ID | MEM_ALLOC` (kernel) marks
            // pointers into program-owned objects (`bpf_obj_new`,
            // `bpf_per_cpu_ptr` of a local `__percpu_kptr`). The
            // kernel allows direct field stores via `btf_struct_access`
            // — no field-table check needed on our side. Without this,
            // `percpu_alloc_array::test_array_map_2`'s `v->c = 1`
            // FRs.
            let is_mem_alloc = base_ty.ptr_flags().contains(PtrFlags::MEM_ALLOC);
            // Conntrack types: `nf_conn___init` is the transient
            // init-state from `bpf_skb_ct_alloc` / `bpf_xdp_ct_alloc`
            // (pre-insert), `nf_conn` is the post-insert form. Kernel
            // admits store of the writable fields (status, mark,
            // timeout) on both. Without mem_region_model entries,
            // treat them like "unknown" for store purposes.
            let store_skip = matches!(
                base_ty,
                PtrToBtfId {
                    // `tcp_sock`: the struct_ops sk arg promoted from
                    // `sock` for tcp_congestion_ops (see runner.rs
                    // struct_ops_entry_args). The kernel's
                    // `bpf_tcp_ca_btf_struct_access` admits writes to the
                    // CA state region (icsk_ca_priv) through it; we have no
                    // tcp_sock mem_region layout, so treat it lax like
                    // "unknown" — the same over-acceptance the arg carried
                    // as "unknown" before the promotion (no new unsoundness
                    // for this arg). Closes bpf_dctcp_cwnd_event's ca-state
                    // store.
                    type_name: "nf_conn___init" | "nf_conn" | "tcp_sock",
                    ..
                }
            );
            if !is_unknown
                && !store_skip
                && !is_mem_alloc
                && !mem_region_model::is_valid_mem_region_read(state.types.get(base), off, size)
            {
                error!(
                    "Invalid BTF-typed write at pc {}: {:?} offset {} size {}",
                    pc, base_ty, off, size
                );
                env.fail(VerificationError::UnsafeGenericStore {
                    pc,
                    base,
                    off,
                    base_type: base_ty,
                });
            }
        }
        _ => {
            error!(
                "Unsafe store at pc {}: base {:?}+{} has non-pointer type {:?}",
                pc, base, off, base_ty
            );
            env.fail(VerificationError::UnsafeGenericStore {
                pc,
                base,
                off,
                base_type: base_ty,
            });
        }
    }
}
