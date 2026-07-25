// src/analysis/transfer/call/kfunc_protos.rs
//
// Kfunc proto table (`get_kfunc_proto`) and prog-type allowlist constants.

use super::signatures::pairs;
use super::signatures::{ArgKind::*, CallFlags, CallProto, IterArgExpect, RetKind, SideEffect};
use crate::analysis::machine::stack_state::{DynptrKind, IrqKfuncClass, IterKind};
use crate::parsing::btf::SpecialFieldKind;

const CPUMASK_KFUNC_PROG_TYPES: [crate::ast::ProgramKind; 5] = [
    crate::ast::ProgramKind::Syscall,
    crate::ast::ProgramKind::Tracing,
    crate::ast::ProgramKind::Tracepoint,
    crate::ast::ProgramKind::PerfEvent,
    // sched_ext implementations call bpf_cpumask_test_cpu and
    // friends on idle masks fetched via scx_bpf_get_idle_cpumask.
    crate::ast::ProgramKind::StructOps,
];

/// Cgroup kfunc family allowlist. Mirrors the kernel's cgroup_kfunc_set
/// registration: tracing/tracepoint/perf_event/syscall/struct_ops (the
/// cpumask base) **plus LSM** — kernel registers the cgroup kfunc id_set
/// against BPF_PROG_TYPE_LSM (selftests like
/// iters_css_task::iter_css_task_for_each + test_task_under_cgroup::lsm_run
/// rely on LSM hooks calling bpf_cgroup_from_id/_acquire). Broken out
/// from the cpumask alias so the LSM addition doesn't bleed into cpumask
/// (cpumask kfuncs are not registered for LSM upstream).
const CGROUP_KFUNC_PROG_TYPES: [crate::ast::ProgramKind; 6] = [
    crate::ast::ProgramKind::Syscall,
    crate::ast::ProgramKind::Tracing,
    crate::ast::ProgramKind::Tracepoint,
    crate::ast::ProgramKind::PerfEvent,
    crate::ast::ProgramKind::StructOps,
    crate::ast::ProgramKind::Lsm,
];

/// Task kfunc family allowlist. Mirrors the kernel's
/// `tasks_kfunc_set` registration: tracing (fentry/fexit/tp_btf), LSM,
/// tracepoint, perf_event, syscall, struct_ops. LSM is added vs the
/// cpumask/cgroup list because `local_storage.c` exercises
/// `bpf_get_current_task_btf` from `lsm.s/*` hooks.
const TASK_KFUNC_PROG_TYPES: [crate::ast::ProgramKind; 6] = [
    crate::ast::ProgramKind::Syscall,
    crate::ast::ProgramKind::Tracing,
    crate::ast::ProgramKind::Tracepoint,
    crate::ast::ProgramKind::PerfEvent,
    crate::ast::ProgramKind::Lsm,
    crate::ast::ProgramKind::StructOps,
];

/// LSM-only kfunc family — `bpf_path_d_path`, `bpf_get_task_exe_file`,
/// `bpf_put_file`. Kernel registers these in `bpf_lsm_kfunc_set` only.
/// `verifier_vfs_reject.c::path_d_path_kfunc_non_lsm` calls
/// `bpf_path_d_path` from `fentry/vfs_open` and the kernel rejects
/// ("calling kernel function bpf_path_d_path is not allowed").
const LSM_ONLY_KFUNC_PROG_TYPES: [crate::ast::ProgramKind; 1] = [crate::ast::ProgramKind::Lsm];

/// `bpf_dynptr_from_skb` allowlist. The kfunc is registered for
/// program types that receive a skb-shaped context — sched_cls/act
/// (tc), socket_filter, cgroup_skb, lwt_*, sk_skb, sock_ops, sk_msg,
/// flow_dissector, netfilter, and Tracing (tp_btf hooks like
/// `kfree_skb`/`consume_skb` whose first arg is `struct sk_buff *`).
const SKB_DYNPTR_KFUNC_PROG_TYPES: [crate::ast::ProgramKind; 13] = [
    crate::ast::ProgramKind::SchedCls,
    crate::ast::ProgramKind::SchedAct,
    crate::ast::ProgramKind::SocketFilter,
    crate::ast::ProgramKind::CgroupSkb,
    crate::ast::ProgramKind::LwtIn,
    crate::ast::ProgramKind::LwtOut,
    crate::ast::ProgramKind::LwtXmit,
    crate::ast::ProgramKind::SkSkb,
    crate::ast::ProgramKind::SockOps,
    crate::ast::ProgramKind::SkMsg,
    crate::ast::ProgramKind::FlowDissector,
    // Netfilter passes `struct sk_buff *` via `bpf_nf_ctx.skb`;
    // upstream `verifier_netfilter_ctx::with_valid_ctx_access_test6`
    // is `__success` calling `bpf_dynptr_from_skb` from a netfilter
    // hook.
    crate::ast::ProgramKind::Netfilter,
    // tp_btf hooks like `kfree_skb`/`consume_skb` receive
    // `struct sk_buff *` as their first arg; kernel allows
    // bpf_dynptr_from_skb here. dynptr_success::test_dynptr_skb_tp_btf
    // exercises this combination.
    crate::ast::ProgramKind::Tracing,
];

/// `bpf_dynptr_from_xdp` allowlist — only XDP programs receive
/// `xdp_md *` context.
const XDP_DYNPTR_KFUNC_PROG_TYPES: [crate::ast::ProgramKind; 1] = [crate::ast::ProgramKind::Xdp];

/// Sched_ext kfunc family allowlist. The kernel registers most
/// `scx_bpf_*` kfuncs against the sched_ext class. A subset (notably
/// `scx_bpf_create_dsq` / `_destroy_dsq` / `_exit_bstr`) is also exposed
/// to `BPF_PROG_TYPE_SYSCALL` — see `prog_run.bpf.c`. We accept both for
/// every scx_bpf_* proto rather than tracking the per-kfunc subdivision;
/// the corpus has no test that distinguishes them, and broadening here
/// cannot produce a false_accept for any current entry.
const SCHED_EXT_KFUNC_PROG_TYPES: [crate::ast::ProgramKind; 2] = [
    crate::ast::ProgramKind::StructOps,
    crate::ast::ProgramKind::Syscall,
];

/// Sock-ops-only kfuncs (kernel `bpf_sock_ops_kfunc_set` in
/// net/core/filter.c). Only `bpf_sock_ops_enable_tx_tstamp` lives here
/// today.
const SOCK_OPS_KFUNC_PROG_TYPES: [crate::ast::ProgramKind; 1] = [crate::ast::ProgramKind::SockOps];

/// Kfunc prototypes indexed by kfunc name. Returns `None` for kfuncs not
/// yet on the proto path — the caller falls back to the legacy bespoke
/// dispatch in `kfunc.rs`.
pub fn get_kfunc_proto(name: &str) -> Option<CallProto> {
    Some(match name {
        // Preempt-region kfuncs (kernel verifier.c v6.15 ~L13560).
        // No args; PREEMPT_DISABLE / PREEMPT_ENABLE drive the
        // `active_preempt_locks` state machine in `apply_pre_call_lock_flags`.
        "bpf_preempt_disable" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .flags(CallFlags::PREEMPT_DISABLE)
        }

        "bpf_preempt_enable" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .flags(CallFlags::PREEMPT_ENABLE)
        }

        // IRQ-region kfuncs (kernel verifier.c v6.15 ~L1184).
        //
        // void bpf_local_irq_save(unsigned long *flags)
        // void bpf_local_irq_restore(unsigned long *flags)
        //
        // The validator (`IrqFlagArg`) enforces stack-pointer arg shape +
        // uninit/init slot state + LIFO ordering; the side-effect handler
        // mints the id, stamps the slot, and pushes/pops `acquired_irq_ids`.
        "bpf_local_irq_save" => CallProto::with_args([
            IrqFlagArg {
                uninit: true,
                kfunc_class: IrqKfuncClass::Native,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .side_effects(&[SideEffect::IrqSaveOnArg {
            arg: 0,
            kfunc_class: IrqKfuncClass::Native,
        }]),

        "bpf_local_irq_restore" => CallProto::with_args([
            IrqFlagArg {
                uninit: false,
                kfunc_class: IrqKfuncClass::Native,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .side_effects(&[SideEffect::IrqRestoreFromArg {
            arg: 0,
            kfunc_class: IrqKfuncClass::Native,
        }]),

        // ---- bpf_res_spin_lock (resilient queued spin lock, kernel
        // verifier.c v6.15 L8271+ `process_spin_lock` is_res_lock arm
        // and L13455 push_stack state-fork). Returns int (0 = acquired,
        // negative = failed-to-acquire); the call-site transfer forks
        // the state into success (R0=0, lock pushed) and failure
        // (R0 ∈ [-MAX_ERRNO, -1], no lock pushed) branches.
        "bpf_res_spin_lock" => CallProto::with_args([
            ResSpinLockArg { is_irq: false },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .flags(CallFlags::RES_SPIN_LOCK_ACQUIRE),

        "bpf_res_spin_unlock" => CallProto::with_args([
            ResSpinLockArg { is_irq: false },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .flags(CallFlags::RES_SPIN_LOCK_RELEASE),

        // _irqsave variant: arg #1 is also an IRQ-flag stack pointer
        // (uninit at acquire, popped at restore). Combines the
        // res-lock state-fork with the IRQ-flag stamp; class is
        // `IrqKfuncClass::Lock` so a `bpf_local_irq_restore`
        // (Native class) cannot release this flag and vice-versa
        // (kernel "irq flag acquired by … kfuncs cannot be restored …").
        "bpf_res_spin_lock_irqsave" => CallProto::with_args([
            ResSpinLockArg { is_irq: true },
            IrqFlagArg {
                uninit: true,
                kfunc_class: IrqKfuncClass::Lock,
            },
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .flags(CallFlags::RES_SPIN_LOCK_ACQUIRE)
        .side_effects(&[SideEffect::IrqSaveOnArg {
            arg: 1,
            kfunc_class: IrqKfuncClass::Lock,
        }]),

        "bpf_res_spin_unlock_irqrestore" => CallProto::with_args([
            ResSpinLockArg { is_irq: true },
            IrqFlagArg {
                uninit: false,
                kfunc_class: IrqKfuncClass::Lock,
            },
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .flags(CallFlags::RES_SPIN_LOCK_RELEASE)
        .side_effects(&[SideEffect::IrqRestoreFromArg {
            arg: 1,
            kfunc_class: IrqKfuncClass::Lock,
        }]),

        // RCU read-side kfuncs (kernel `verifier.c` v6.15: registered
        // in `common_btf_ids` as `KF_RCU_PROTECTS_ALLOC`/no-arg). The
        // `BPF_PSEUDO_KFUNC_CALL` form is what `__ksym extern void
        // bpf_rcu_read_lock(void);` resolves to in refcounted_kptr.c.
        // Reuse the same RCU_READ_LOCK / _UNLOCK depth-counter
        // machinery used by the helper-form (transfer.rs ~L1226).
        "bpf_rcu_read_lock" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .flags(CallFlags::RCU_READ_LOCK)
        }

        "bpf_rcu_read_unlock" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .flags(CallFlags::RCU_READ_UNLOCK)
        }

        "bpf_set_exception_callback" => CallProto::with_args([
            PtrToCallback, // R1: subprog ptr (PSEUDO_FUNC)
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::SetExceptionCallbackFromArg { arg: 0 }]),

        // ---- Ringbuf dynptrs ----
        //
        // void bpf_ringbuf_reserve_dynptr(struct bpf_map *rb, u32 size,
        //                                 u64 flags, struct bpf_dynptr *ptr)
        //
        // R4 is the dynptr ctor sink. Mints a ref_id, stamps a
        // `Ringbuf` annotation on the stack pair. Returns 0/-errno;
        // failure path leaves the slot initialized but the dynptr's
        // internal data NULL — runtime concern, not a verifier one.
        "bpf_ringbuf_reserve_dynptr" => CallProto::with_args([
            ConstMapPtr, // R1: ringbuf map
            Anything,    // R2: size
            Anything,    // R3: flags
            DynptrArg {
                uninit: true,
                rdwr_only: false,
            }, // R4: &dynptr
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::DynptrInitOnArg {
            arg: 3,
            kind: DynptrKind::Ringbuf,
            rdonly: false,
        }]),

        // void bpf_ringbuf_submit_dynptr(struct bpf_dynptr *ptr, u64 flags)
        "bpf_ringbuf_submit_dynptr" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            }, // R1: &dynptr
            Anything, // R2: flags
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .side_effects(&[SideEffect::DynptrReleaseFromArg { arg: 0 }]),

        // void bpf_ringbuf_discard_dynptr(struct bpf_dynptr *ptr, u64 flags)
        "bpf_ringbuf_discard_dynptr" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            }, // R1: &dynptr
            Anything, // R2: flags
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .side_effects(&[SideEffect::DynptrReleaseFromArg { arg: 0 }]),

        // ---- Local-cluster dynptrs ----
        //
        // int bpf_dynptr_from_mem(void *data, u32 size, u64 flags,
        //                         struct bpf_dynptr *ptr)
        //
        // Wraps a caller-owned buffer (stack/map/packet) in a Local
        // dynptr. R1 is the buffer; mem-size-pair (R1,R2) proves that
        // `size` bytes are accessible. No ref tracking — Local dynptrs
        // are pure metadata and need no release.
        "bpf_dynptr_from_mem" => CallProto::with_args([
            PtrToMem,        // R1: source buffer
            ConstSizeOrZero, // R2: size (kernel accepts 0 — returns -EINVAL at runtime, not at verification)
            Anything,        // R3: flags (rdonly bit etc. — not modeled yet)
            DynptrArg {
                uninit: true,
                rdwr_only: false,
            }, // R4: &dynptr
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::DynptrInitOnArg {
            arg: 3,
            kind: DynptrKind::Local,
            rdonly: false,
        }])
        .mem_size_pairs(&pairs::DYNPTR_FROM_MEM),

        // int bpf_dynptr_read(void *dst, u32 len, const struct bpf_dynptr *src,
        //                     u32 offset, u64 flags)
        //
        // Copies `len` bytes from `src` dynptr (at `offset`) into `dst`.
        // Pair (R1,R2) bounds the dst write. Reads from any dynptr kind
        // including rdonly.
        "bpf_dynptr_read" => CallProto::with_args([
            PtrToUninitMem,  // R1: dst
            ConstSizeOrZero, // R2: len (0 accepted; runtime returns 0)
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            }, // R3: src dynptr
            Anything,        // R4: offset
            Anything,        // R5: flags
        ])
        .ret(RetKind::Scalar)
        .mem_size_pairs(&pairs::DYNPTR_READ),

        // int bpf_dynptr_write(const struct bpf_dynptr *dst, u32 offset,
        //                      void *src, u32 len, u64 flags)
        //
        // Copies `len` bytes from `src` into `dst` dynptr at `offset`.
        // Kernel doesn't enforce rdwr at verify time (no `__rdwr` on the
        // kfunc) — runtime returns -EINVAL when dst is rdonly. Tests
        // like test_skb_readonly / test_dynptr_skb_tp_btf rely on the
        // verifier accepting the call statically and then asserting on
        // the runtime errno.
        "bpf_dynptr_write" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            }, // R1: dst dynptr
            Anything,        // R2: offset
            PtrToMem,        // R3: src
            ConstSizeOrZero, // R4: len (0 accepted)
            Anything,        // R5: flags
        ])
        .ret(RetKind::Scalar)
        .mem_size_pairs(&pairs::DYNPTR_WRITE),

        // ---- XDP metadata kfuncs (NIC-driven RX metadata getters) ----
        //
        // All three take an XDP context plus output ptr(s). Used by
        // xdp_metadata.c, xdp_metadata2.c (freplace), xdp_hw_metadata.c.
        // Output buffer size is implicit in the C type; modeled as
        // PtrToUninitMem (writable mem of any size).
        "bpf_xdp_metadata_rx_timestamp" => {
            CallProto::with_args([PtrToCtx, PtrToUninitMem, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&XDP_DYNPTR_KFUNC_PROG_TYPES)
        }

        "bpf_xdp_metadata_rx_hash" => {
            CallProto::with_args([PtrToCtx, PtrToUninitMem, PtrToUninitMem, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&XDP_DYNPTR_KFUNC_PROG_TYPES)
        }

        "bpf_xdp_metadata_rx_vlan_tag" => {
            CallProto::with_args([PtrToCtx, PtrToUninitMem, PtrToUninitMem, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&XDP_DYNPTR_KFUNC_PROG_TYPES)
        }

        // int bpf_dynptr_clone(const struct bpf_dynptr *ptr,
        //                      struct bpf_dynptr *clone__init)
        //
        // Kernel `bpf_dynptr_clone` propagates source `type`, `rdonly`
        // bit, and `ref_obj_id` onto the clone slot — sharing
        // `ref_obj_id` is what lets a `bpf_ringbuf_submit_dynptr(parent)`
        // sweep both slots (kernel walks every dynptr stack slot whose
        // `ref_obj_id` matches the released id). The slice-invalidation
        // path ties on `dynptr_id` instead: each dynptr keeps its own
        // per-instance id for slices, but `collect_packet_dynptr_ids`
        // returns ids of *all* Skb/Xdp slots so packet mutators sweep
        // the clone's slices too via the propagated `kind`.
        "bpf_dynptr_clone" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            },
            DynptrArg {
                uninit: true,
                rdwr_only: false,
            },
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::DynptrCloneOnArg {
            src_arg: 0,
            dst_arg: 1,
        }]),

        // int bpf_dynptr_copy(struct bpf_dynptr *dst, u32 dst_off,
        //                     const struct bpf_dynptr *src, u32 src_off,
        //                     u32 len)
        //
        // Copies `len` bytes from src+src_off to dst+dst_off. Both dynptrs
        // must be initialized; dst must be writable (rdwr_only). Returns
        // 0 on success, negative errno on bounds/dst-rdonly. Used in
        // dynptr_success.c::test_dynptr_copy.
        "bpf_dynptr_copy" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: true,
            }, // R1: dst (RW)
            Anything, // R2: dst_off
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            }, // R3: src (any)
            Anything, // R4: src_off
            Anything, // R5: len
        ])
        .ret(RetKind::Scalar),

        // int bpf_dynptr_adjust(const struct bpf_dynptr *ptr,
        //                        u32 start, u32 end)
        //
        // Trims the dynptr's view to [start, end). Read-only on the
        // dynptr (mutates internal offset/size, not the buffer), so any
        // initialized dynptr (including rdonly) is acceptable. The
        // `__failure` sibling (`dynptr_fail::dynptr_adjust_invalid`)
        // passes `{}` — our `DynptrArg{uninit:false}` rejects it.
        "bpf_dynptr_adjust" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            }, // R1: ptr
            Anything, // R2: start
            Anything, // R3: end
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // bool bpf_dynptr_is_null(const struct bpf_dynptr *ptr)
        "bpf_dynptr_is_null" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // bool bpf_dynptr_is_rdonly(const struct bpf_dynptr *ptr)
        "bpf_dynptr_is_rdonly" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // __u32 bpf_dynptr_size(const struct bpf_dynptr *ptr)
        "bpf_dynptr_size" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_dynptr_clone deliberately NOT registered. Two `__failure`
        // siblings in `dynptr_fail.c` rely on kernel-only rejection
        // mechanisms we don't model:
        //   - `clone_invalidate1`: kernel propagates parent invalidation
        //     to all clones (after `bpf_ringbuf_submit_dynptr(&ptr)`,
        //     reads through the clone fail). We don't track parent/clone
        //     lineage on dynptr slots.
        //   - `clone_xdp_packet_data`: kernel propagates source `Xdp`
        //     kind onto the clone, so subsequent `bpf_xdp_adjust_head`
        //     invalidates the clone's slice. We'd default the clone to
        //     `Local` and miss the invalidation cascade.
        // Registering the proto without these mechanisms unmasks both as
        // PASS → FALSE_ACCEPT. Closing `test_dynptr_clone` (1 FR) isn't
        // worth opening 2 FAs; revisit when clone-lineage is modeled.

        // void *bpf_dynptr_data(const struct bpf_dynptr *ptr, u32 offset, u32 len)
        //
        // Returns a pointer into the dynptr's backing memory bounded by
        // `len` (R3), or NULL on failure. Used for Local/Ringbuf dynptrs
        // (skb/xdp must use bpf_dynptr_slice). Caller null-checks before
        // dereferencing — RET_NULL on the proto.
        "bpf_dynptr_data" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            }, // R1: src dynptr
            Anything,  // R2: offset
            ConstSize, // R3: len (bounds the returned pointer)
            DontCare,
            DontCare,
        ])
        .ret(RetKind::PtrToAllocMemFromArg { size_arg: 2 })
        .flags(CallFlags::RET_NULL),

        // ---- skb / xdp dynptrs ----
        //
        // int bpf_dynptr_from_skb(struct __sk_buff *skb, u64 flags,
        //                         struct bpf_dynptr *ptr)
        //
        // Wraps skb data as a dynptr. We force rdonly=true here:
        // matches kernel default for read-only skb program types
        // (socket filter, tracing); SCHED_CLS / SCHED_ACT wrap as
        // rdwr but require per-program-type modeling we defer.
        "bpf_dynptr_from_skb" => CallProto::with_args([
            PtrToCtx, // R1: skb context
            Anything, // R2: flags
            DynptrArg {
                uninit: true,
                rdwr_only: false,
            }, // R3: &dynptr
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::DynptrInitOnArg {
            arg: 2,
            kind: DynptrKind::Skb,
            rdonly: true,
        }])
        .prog_type_allowlist(&SKB_DYNPTR_KFUNC_PROG_TYPES),

        // int bpf_dynptr_from_xdp(struct xdp_md *xdp, u64 flags,
        //                         struct bpf_dynptr *ptr)
        //
        // Wraps xdp frame data as a dynptr. XDP programs CAN mutate
        // packet data, so the dynptr is read-write — matches kernel
        // (no DYNPTR_RDONLY_BIT set in `bpf_dynptr_init` for XDP type).
        "bpf_dynptr_from_xdp" => CallProto::with_args([
            PtrToCtx, // R1: xdp context
            Anything, // R2: flags
            DynptrArg {
                uninit: true,
                rdwr_only: false,
            }, // R3: &dynptr
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::DynptrInitOnArg {
            arg: 2,
            kind: DynptrKind::Xdp,
            rdonly: false,
        }])
        .prog_type_allowlist(&XDP_DYNPTR_KFUNC_PROG_TYPES),

        // ---- Open-coded iterators ----
        //
        // `bpf_iter_*_new(&it, ...)` — Uninit→Active. The iter struct is
        // stack-allocated by the program; the side-effect zero-inits its
        // bytes and stamps a fresh iter_id. Returns 0/-errno: applier
        // sets R0 = scalar; legacy bespoke handler tightened the bound to
        // [-MAX_ERRNO, 0] which the proto applier doesn't reproduce —
        // dropping that bound is intentional (matches dynptr ctor bounds
        // and isn't load-bearing for the test corpus).
        //
        // R2..R5 vary per-kind (num: start/end/step, task/css: opaque
        // ptrs). We accept any scalar/ptr there with `Anything`; the
        // kernel does deeper checks but those don't affect our
        // soundness for the slot-state model.
        "bpf_iter_num_new" => CallProto::with_args([
            IterArg {
                kind: IterKind::Num,
                expected: IterArgExpect::Uninit,
            },
            Anything,
            Anything,
            Anything,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::IterInitOnArg {
            arg: 0,
            kind: IterKind::Num,
        }]),

        // bpf_iter_task_new: kernel takes an RCU read lock for the
        // iter's lifetime so KF_RCU consumers (`bpf_kfunc_rcu_task_test`)
        // called between _new and _destroy don't need an explicit
        // `bpf_rcu_read_lock()`. Modeled here as RCU_READ_LOCK on
        // _new + RCU_READ_UNLOCK on _destroy. Closes the
        // `iters_testmod.c::iter_next_rcu` sequence.
        // bpf_iter_task_new is KF_RCU_PROTECTED in the kernel: it does
        // NOT take an RCU read lock itself (was a prior modeling
        // mistake); it only reads in_rcu_cs at call-time and stamps the
        // iter slot with MEM_RCU (trusted) or PTR_UNTRUSTED accordingly
        // (verifier.c v6.15 `mark_stack_slots_iter` ~L1041). Slot-trust
        // logic lives in the IterInitOnArg side-effect handler — it
        // calls `state.in_rcu_read_section()` and sets
        // `IteratorSlot.untrusted` for `IterKind::Task`/`Css`. Subsequent
        // `_next` calls reject on UNTRUSTED. Programs that rely on the
        // implicit kernel-held RCU CS (non-sleepable kprobe/raw_tp/etc.)
        // get `rcu_read_depth = 1` at entry from `analysis::mod`.
        "bpf_iter_task_new" => CallProto::with_args([
            IterArg {
                kind: IterKind::Task,
                expected: IterArgExpect::Uninit,
            },
            Anything,
            Anything,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::IterInitOnArg {
            arg: 0,
            kind: IterKind::Task,
        }]),

        "bpf_iter_css_new" => CallProto::with_args([
            IterArg {
                kind: IterKind::Css,
                expected: IterArgExpect::Uninit,
            },
            Anything,
            Anything,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::IterInitOnArg {
            arg: 0,
            kind: IterKind::Css,
        }]),

        "bpf_iter_bits_new" => CallProto::with_args([
            IterArg {
                kind: IterKind::Bits,
                expected: IterArgExpect::Uninit,
            },
            Anything,
            Anything,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::IterInitOnArg {
            arg: 0,
            kind: IterKind::Bits,
        }]),

        // `bpf_iter_*_next(&it)` — accepts Active or Drained; the
        // dispatcher forks Active into non-NULL (R0 = PtrToAllocMem{elem_size},
        // slot stays Active) and NULL (R0 = 0, slot → Drained), and on
        // Drained input collapses to the NULL-only successor (kernel
        // semantics: a drained iterator just keeps returning NULL).
        // Without `ActiveOrDrained`, programs that call `_next` after a
        // post-loop unrolled iteration (iters.c::iter_pragma_unroll_loop)
        // FR'd because the static unroll re-enters _next on the Drained
        // slot a second time.
        // Element sizes mirror the bespoke handler: num=4 (int*),
        // bits=8 (u64*), task/css=8 (placeholder pointer-width until
        // PtrToBtfId per-kind typing in a future phase).
        "bpf_iter_num_next" => CallProto::with_args([
            IterArg {
                kind: IterKind::Num,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::IterNextElem {
            iter_arg: 0,
            elem_size: 4,
        }),

        "bpf_iter_task_next" => CallProto::with_args([
            IterArg {
                kind: IterKind::Task,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        // Returns `struct task_struct *`. Kernel verifies tasks held
        // across an iter as RCU-protected (the iter holds an RCU
        // read lock for its lifetime); KF_RCU consumers
        // (`bpf_kfunc_rcu_task_test`) accept, KF_TRUSTED_ARGS
        // consumers (`bpf_kfunc_trusted_task_test`) reject. Closes
        // `iter_next_rcu` while keeping `iter_next_rcu_not_trusted`
        // rejected via the new flag enforcement.
        .ret(RetKind::IterNextBtfId {
            iter_arg: 0,
            type_name: "task_struct",
            flags: crate::analysis::machine::reg_types::PtrFlags::RCU,
        }),

        // ---- bpf_iter_task_vma_* (Phase C iters_testmod.c) ----
        // 8-byte opaque iter struct (kernel-internal state lives in
        // bpf_iter_task_vma_kern). Returns `struct vm_area_struct *`
        // marked TRUSTED — the kernel iter holds the task's mmap
        // semaphore for the iter's lifetime, so the vma is
        // safe-to-deref. KF_TRUSTED_ARGS consumers
        // (`bpf_kfunc_trusted_vma_test`) accept.
        "bpf_iter_task_vma_new" => CallProto::with_args([
            IterArg {
                kind: IterKind::TaskVma,
                expected: IterArgExpect::Uninit,
            },
            Anything,
            Anything,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::IterInitOnArg {
            arg: 0,
            kind: IterKind::TaskVma,
        }]),

        "bpf_iter_task_vma_next" => CallProto::with_args([
            IterArg {
                kind: IterKind::TaskVma,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::IterNextBtfId {
            iter_arg: 0,
            type_name: "vm_area_struct",
            flags: crate::analysis::machine::reg_types::PtrFlags::TRUSTED,
        }),

        "bpf_iter_task_vma_destroy" => CallProto::with_args([
            IterArg {
                kind: IterKind::TaskVma,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .side_effects(&[SideEffect::IterDestroyOnArg { arg: 0 }]),

        // ---- bpf_iter_kmem_cache_* (kmem_cache_iter.c) ----
        // 8-byte opaque iter struct. `_next` returns `struct kmem_cache *`
        // marked TRUSTED — the kernel iter holds the slab_mutex while
        // walking the slab cache list, so the returned cache is
        // safe-to-deref via BTF field loads (s->name, s->size).
        "bpf_iter_kmem_cache_new" => CallProto::with_args([
            IterArg {
                kind: IterKind::KmemCache,
                expected: IterArgExpect::Uninit,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::IterInitOnArg {
            arg: 0,
            kind: IterKind::KmemCache,
        }]),

        "bpf_iter_kmem_cache_next" => CallProto::with_args([
            IterArg {
                kind: IterKind::KmemCache,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::IterNextBtfId {
            iter_arg: 0,
            type_name: "kmem_cache",
            flags: crate::analysis::machine::reg_types::PtrFlags::TRUSTED,
        }),

        "bpf_iter_kmem_cache_destroy" => CallProto::with_args([
            IterArg {
                kind: IterKind::KmemCache,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .side_effects(&[SideEffect::IterDestroyOnArg { arg: 0 }]),

        // ---- testmod consumer kfuncs (Phase C iters_testmod.c) ----
        //
        // The kernel registers these in `bpf_testmod_kfunc_set` to
        // exercise the kfunc-arg trust-band enforcement:
        //   - bpf_kfunc_trusted_vma_test  : KF_TRUSTED_ARGS, takes
        //     `struct vm_area_struct *` — accepts only TRUSTED.
        //   - bpf_kfunc_trusted_task_test : KF_TRUSTED_ARGS, takes
        //     `struct task_struct *`     — rejects RCU-flagged
        //     (catches `iter_next_rcu_not_trusted`).
        //   - bpf_kfunc_trusted_num_test  : KF_TRUSTED_ARGS, takes
        //     `int *`                    — rejects PtrToAllocMem
        //     (catches `iter_next_ptr_mem_not_trusted`).
        //   - bpf_kfunc_rcu_task_test     : KF_RCU, takes
        //     `struct task_struct *`     — accepts TRUSTED or RCU
        //     (closes `iter_next_rcu`).
        "bpf_kfunc_trusted_vma_test" => CallProto::with_args([
            PtrToBtfIdNamed {
                type_name: "vm_area_struct",
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .flags(CallFlags::TRUSTED_ARGS),

        "bpf_kfunc_trusted_task_test" => CallProto::with_args([
            PtrToBtfIdNamed {
                type_name: "task_struct",
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .flags(CallFlags::TRUSTED_ARGS),

        "bpf_kfunc_trusted_num_test" => CallProto::with_args([
            // Kernel signature is `int *ptr`. We don't have a
            // dedicated typed-int-pointer ArgKind; PtrToBtfId is the
            // closest non-anything kind, and the trust-band gate
            // rejects PtrToAllocMem (the only thing
            // `bpf_iter_num_next` can return) before the
            // PtrToBtfId-shape check would even fire.
            Anything, DontCare, DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Void)
        .flags(CallFlags::TRUSTED_ARGS),

        "bpf_kfunc_rcu_task_test" => CallProto::with_args([
            PtrToBtfIdNamed {
                type_name: "task_struct",
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .flags(CallFlags::RCU),

        // bpf_iter_css_next(&it) → struct cgroup_subsys_state *
        // Kernel KF_RCU: returned pointer is RCU-protected (must be in
        // RCU CS). Use IterNextBtfId so chained loads through pos
        // (`pos->cgroup`, etc. — iters_css::iter_css_for_each) get
        // typed via the cgroup_subsys_state struct rather than dying
        // at PtrToAllocMem{8}'s opaque memory.
        "bpf_iter_css_next" => CallProto::with_args([
            IterArg {
                kind: IterKind::Css,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::IterNextBtfId {
            iter_arg: 0,
            type_name: "cgroup_subsys_state",
            flags: crate::analysis::machine::reg_types::PtrFlags::RCU,
        }),

        "bpf_iter_bits_next" => CallProto::with_args([
            IterArg {
                kind: IterKind::Bits,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::IterNextElem {
            iter_arg: 0,
            elem_size: 8,
        }),

        // `bpf_iter_*_destroy(&it)` — accept Active|Drained, transition
        // back to Uninit. Calling on an Uninit slot is a REJECT (mirrors
        // kernel "destroy on uninitialized").
        "bpf_iter_num_destroy" => CallProto::with_args([
            IterArg {
                kind: IterKind::Num,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .side_effects(&[SideEffect::IterDestroyOnArg { arg: 0 }]),

        // No RCU_READ_UNLOCK side effect — iter_task_new doesn't take a
        // CS in our updated model (see comment there).
        "bpf_iter_task_destroy" => CallProto::with_args([
            IterArg {
                kind: IterKind::Task,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .side_effects(&[SideEffect::IterDestroyOnArg { arg: 0 }]),

        "bpf_iter_css_destroy" => CallProto::with_args([
            IterArg {
                kind: IterKind::Css,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .side_effects(&[SideEffect::IterDestroyOnArg { arg: 0 }]),

        // ---- bpf_iter_css_task_* (iters_css_task.c) ----
        // int bpf_iter_css_task_new(struct bpf_iter_css_task *it,
        //                           struct cgroup_subsys_state *css,
        //                           unsigned int flags)
        // KF_ITER_NEW | KF_TRUSTED_ARGS in the kernel (NOT KF_RCU_PROTECTED).
        // Allowlist-restricted to LSM / iter / sleepable programs
        // (`check_css_task_iter_allowlist`); the iter holds its own
        // `css_task_iter` lock so its slot trust does not depend on
        // in_rcu_cs at init time. `_next` returns `struct task_struct *`
        // (RCU-flagged); KF_RCU consumers accept, KF_TRUSTED_ARGS reject.
        "bpf_iter_css_task_new" => CallProto::with_args([
            IterArg {
                kind: IterKind::CssTask,
                expected: IterArgExpect::Uninit,
            },
            Anything,
            Anything,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::IterInitOnArg {
            arg: 0,
            kind: IterKind::CssTask,
        }]),

        "bpf_iter_css_task_next" => CallProto::with_args([
            IterArg {
                kind: IterKind::CssTask,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::IterNextBtfId {
            iter_arg: 0,
            type_name: "task_struct",
            flags: crate::analysis::machine::reg_types::PtrFlags::RCU,
        }),

        "bpf_iter_css_task_destroy" => CallProto::with_args([
            IterArg {
                kind: IterKind::CssTask,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .side_effects(&[SideEffect::IterDestroyOnArg { arg: 0 }]),

        "bpf_iter_bits_destroy" => CallProto::with_args([
            IterArg {
                kind: IterKind::Bits,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .side_effects(&[SideEffect::IterDestroyOnArg { arg: 0 }]),

        // ---- testmod_seq iterator family ----
        //
        // testmod-defined open-coded iterator. The kernel registers all
        // four kfuncs in `bpf_testmod_check_kfunc_call`:
        //   - _new   : KF_ITER_NEW
        //   - _next  : KF_ITER_NEXT | KF_RET_NULL
        //   - _destroy: KF_ITER_DESTROY
        //   - _value : reads the iter's stored value; the `it__iter`
        //     param suffix tells the kernel "this is an initialized iter
        //     reference" — accept Active *or* Drained, reject Uninit.
        //     Selftest `testmod_seq_getter_after_bad` covers the post-
        //     destroy case (Uninit → reject); _value's expected =
        //     ActiveOrDrained is what catches both bad calls.
        //
        // int bpf_iter_testmod_seq_new(struct bpf_iter_testmod_seq *it, s64 value, int cnt)
        "bpf_iter_testmod_seq_new" => CallProto::with_args([
            IterArg {
                kind: IterKind::TestmodSeq,
                expected: IterArgExpect::Uninit,
            },
            Anything,
            Anything,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .side_effects(&[SideEffect::IterInitOnArg {
            arg: 0,
            kind: IterKind::TestmodSeq,
        }]),

        // s64 *bpf_iter_testmod_seq_next(struct bpf_iter_testmod_seq *it)
        "bpf_iter_testmod_seq_next" => CallProto::with_args([
            IterArg {
                kind: IterKind::TestmodSeq,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::IterNextElem {
            iter_arg: 0,
            elem_size: 8,
        }),

        // void bpf_iter_testmod_seq_destroy(struct bpf_iter_testmod_seq *it)
        "bpf_iter_testmod_seq_destroy" => CallProto::with_args([
            IterArg {
                kind: IterKind::TestmodSeq,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .side_effects(&[SideEffect::IterDestroyOnArg { arg: 0 }]),

        // s64 bpf_iter_testmod_seq_value(int val, struct bpf_iter_testmod_seq *it__iter)
        // The `__iter` suffix forces the kernel to treat arg #2 (R2 here)
        // as an initialized iter — Active or Drained, never Uninit.
        // Doesn't transition the slot's state.
        "bpf_iter_testmod_seq_value" => CallProto::with_args([
            Anything,
            IterArg {
                kind: IterKind::TestmodSeq,
                expected: IterArgExpect::ActiveOrDrained,
            },
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- Slice cluster ----
        //
        // const void *bpf_dynptr_slice(const struct bpf_dynptr *p,
        //                              u32 offset,
        //                              void *buffer, u32 buffer_size)
        //
        // Returns a pointer into the dynptr's backing memory (fast
        // path, contiguous case) or copies into the caller-provided
        // `buffer` (slow path, fragmented). May be NULL if the slice
        // straddles a non-copyable boundary. Pair (R3,R4) bounds the
        // scratch buffer; the returned pointer is bounded by `R4` —
        // RetKind::PtrToAllocMemFromArg{size_arg=3}.
        "bpf_dynptr_slice" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            }, // R1: src dynptr
            Anything,             // R2: offset
            PtrToUninitMemOrNull, // R3: scratch buffer (NULL OK — `buffer__opt`)
            ConstSize,            // R4: buffer size
            DontCare,
        ])
        .ret(RetKind::PtrToAllocMemFromArgRdonly { size_arg: 3 })
        .flags(CallFlags::RET_NULL)
        .mem_size_pairs(&pairs::DYNPTR_SLICE),

        // void *bpf_dynptr_slice_rdwr(const struct bpf_dynptr *p,
        //                             u32 offset,
        //                             void *buffer, u32 buffer_size)
        //
        // Same as `slice` but rejects rdonly dynptrs. Returns a writable
        // pointer; rdonly tracking on the *result* isn't modeled yet
        // (`PtrToAllocMem` carries no rdonly bit) — defer until a
        // real consumer needs it.
        "bpf_dynptr_slice_rdwr" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: true,
            }, // R1: src dynptr
            Anything,             // R2: offset
            PtrToUninitMemOrNull, // R3: scratch buffer (NULL OK — `buffer__opt`)
            ConstSize,            // R4: buffer size
            DontCare,
        ])
        .ret(RetKind::PtrToAllocMemFromArg { size_arg: 3 })
        .flags(CallFlags::RET_NULL)
        .mem_size_pairs(&pairs::DYNPTR_SLICE),

        // ---- Cpumask kfuncs ----
        //
        // All cpumask kfuncs share the prog-type allowlist
        // (`KF_PROG_TYPE_*` in the kernel): permitted in `syscall`,
        // `tracing` (fentry/fexit/tp_btf/iter), `tracepoint`, and
        // `perf_event`; rejected from `raw_tp` and other prog types
        // that lack a vmlinux BTF context. Validated by
        // `transfer_kfunc_proto` before arg checks.
        //
        // struct bpf_cpumask *bpf_cpumask_create(void)
        // KF_ACQUIRE | KF_RET_NULL — fresh refcounted cpumask, may be
        // NULL on alloc failure. Applier mints a ref_id and returns
        // PtrToCpumaskOrNull; the program must null-check before use.
        "bpf_cpumask_create" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToCpumask)
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // struct bpf_cpumask *bpf_cpumask_acquire(struct bpf_cpumask *p)
        // KF_ACQUIRE | KF_TRUSTED_ARGS — increments refcount on an
        // existing cpumask. Returns the same logical pointer with a
        // fresh ref_id (so the program can release each independently).
        // Not RET_NULL: the kernel guarantees acquire never fails
        // (refcount_t saturating add). R1 must be a non-null,
        // ref-tracked PtrToCpumask.
        "bpf_cpumask_acquire" => {
            CallProto::with_args([PtrToCpumask, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToCpumask)
                .flags(CallFlags::ACQUIRE)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // void bpf_cpumask_release(struct bpf_cpumask *cpumask)
        // KF_RELEASE — drops the refcount. R1 must be a non-null,
        // ref-tracked PtrToCpumask; ReleaseRefFromArg invalidates the
        // ref_id everywhere it's still aliased.
        "bpf_cpumask_release" => {
            CallProto::with_args([PtrToCpumask, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .flags(CallFlags::RELEASE)
                .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }])
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // void bpf_cpumask_set_cpu(u32 cpu, struct bpf_cpumask *cpumask)
        // Mutates the cpumask. R1 = cpu (scalar), R2 = cpumask.
        "bpf_cpumask_set_cpu" => {
            CallProto::with_args([Anything, PtrToCpumask, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask)
        // Read-only query — `PtrToCpumaskRead` accepts both the
        // bpf_cpumask wrapper (PtrToCpumask) and BTF-typed reads
        // (`task->cpus_ptr`).
        "bpf_cpumask_test_cpu" => {
            CallProto::with_args([Anything, PtrToCpumaskRead, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .flags(CallFlags::FASTCALL)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // u32 bpf_cpumask_first(const struct cpumask *cpumask)
        "bpf_cpumask_first" => {
            CallProto::with_args([PtrToCpumaskRead, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .flags(CallFlags::FASTCALL)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // u32 bpf_cpumask_first_zero(const struct cpumask *cpumask)
        // Same shape as `bpf_cpumask_first`, returns first unset cpu.
        // KF_RCU consumer.
        "bpf_cpumask_first_zero" => {
            CallProto::with_args([PtrToCpumaskRead, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .flags(CallFlags::FASTCALL)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // u32 bpf_cpumask_first_and(const struct cpumask *src1,
        //                           const struct cpumask *src2)
        "bpf_cpumask_first_and" => CallProto::with_args([
            PtrToCpumaskRead,
            PtrToCpumaskRead,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .flags(CallFlags::FASTCALL)
        .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES),

        // u32 bpf_cpumask_weight(const struct cpumask *cpumask)
        "bpf_cpumask_weight" => {
            CallProto::with_args([PtrToCpumaskRead, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .flags(CallFlags::FASTCALL)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // u32 bpf_cpumask_any_distribute(const struct cpumask *src)
        "bpf_cpumask_any_distribute" => {
            CallProto::with_args([PtrToCpumaskRead, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .flags(CallFlags::FASTCALL)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // u32 bpf_cpumask_any_and_distribute(const struct cpumask *src1,
        //                                    const struct cpumask *src2)
        "bpf_cpumask_any_and_distribute" => CallProto::with_args([
            PtrToCpumaskRead,
            PtrToCpumaskRead,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .flags(CallFlags::FASTCALL)
        .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES),

        // ---- Read-only predicates (return bool) ----

        // bool bpf_cpumask_equal(const struct cpumask *src1, const struct cpumask *src2)
        "bpf_cpumask_equal" => CallProto::with_args([
            PtrToCpumaskRead,
            PtrToCpumaskRead,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .flags(CallFlags::FASTCALL)
        .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES),

        // bool bpf_cpumask_intersects(const struct cpumask *src1, const struct cpumask *src2)
        "bpf_cpumask_intersects" => CallProto::with_args([
            PtrToCpumaskRead,
            PtrToCpumaskRead,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .flags(CallFlags::FASTCALL)
        .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES),

        // bool bpf_cpumask_subset(const struct cpumask *src1, const struct cpumask *src2)
        "bpf_cpumask_subset" => CallProto::with_args([
            PtrToCpumaskRead,
            PtrToCpumaskRead,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .flags(CallFlags::FASTCALL)
        .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES),

        // bool bpf_cpumask_empty(const struct cpumask *cpumask)
        "bpf_cpumask_empty" => {
            CallProto::with_args([PtrToCpumaskRead, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .flags(CallFlags::FASTCALL)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // bool bpf_cpumask_full(const struct cpumask *cpumask)
        "bpf_cpumask_full" => {
            CallProto::with_args([PtrToCpumaskRead, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .flags(CallFlags::FASTCALL)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // ---- Mutators that modify their first arg (PtrToCpumask) ----

        // void bpf_cpumask_clear_cpu(u32 cpu, struct bpf_cpumask *cpumask)
        "bpf_cpumask_clear_cpu" => {
            CallProto::with_args([Anything, PtrToCpumask, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // bool bpf_cpumask_test_and_set_cpu(u32 cpu, struct bpf_cpumask *cpumask)
        "bpf_cpumask_test_and_set_cpu" => {
            CallProto::with_args([Anything, PtrToCpumask, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // bool bpf_cpumask_test_and_clear_cpu(u32 cpu, struct bpf_cpumask *cpumask)
        "bpf_cpumask_test_and_clear_cpu" => {
            CallProto::with_args([Anything, PtrToCpumask, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // void bpf_cpumask_setall(struct bpf_cpumask *cpumask)
        "bpf_cpumask_setall" => {
            CallProto::with_args([PtrToCpumask, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // void bpf_cpumask_clear(struct bpf_cpumask *cpumask)
        "bpf_cpumask_clear" => {
            CallProto::with_args([PtrToCpumask, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // bool bpf_cpumask_and(struct bpf_cpumask *dst,
        //                      const struct cpumask *src1,
        //                      const struct cpumask *src2)
        "bpf_cpumask_and" => CallProto::with_args([
            PtrToCpumask,
            PtrToCpumaskRead,
            PtrToCpumaskRead,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES),

        // void bpf_cpumask_or(struct bpf_cpumask *dst,
        //                     const struct cpumask *src1,
        //                     const struct cpumask *src2)
        "bpf_cpumask_or" => CallProto::with_args([
            PtrToCpumask,
            PtrToCpumaskRead,
            PtrToCpumaskRead,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES),

        // void bpf_cpumask_xor(struct bpf_cpumask *dst,
        //                      const struct cpumask *src1,
        //                      const struct cpumask *src2)
        "bpf_cpumask_xor" => CallProto::with_args([
            PtrToCpumask,
            PtrToCpumaskRead,
            PtrToCpumaskRead,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES),

        // void bpf_cpumask_copy(struct bpf_cpumask *dst, const struct cpumask *src)
        "bpf_cpumask_copy" => {
            CallProto::with_args([PtrToCpumask, PtrToCpumaskRead, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // int bpf_cpumask_populate(struct cpumask *cpumask,
        //                          void *src, size_t src__sz)
        // R2/R3 form a mem+size pair — kernel rejects "leads to invalid
        // memory access" when sz exceeds the source buffer (matches
        // cpumask_failure::test_populate_invalid_source's __failure
        // expectation). Destination expects writable cpumask wrapper.
        "bpf_cpumask_populate" => {
            CallProto::with_args([PtrToCpumask, PtrToMem, ConstSize, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .mem_size_pairs(&pairs::CPUMASK_POPULATE)
                .prog_type_allowlist(&CPUMASK_KFUNC_PROG_TYPES)
        }

        // ---- Cgroup kfuncs ----
        //
        // Parallels the cpumask family: `RegType::PtrToCgroup{,OrNull}`,
        // acquire/release with ref_id tracking + null-check refinement.
        // All three kfuncs share `CGROUP_KFUNC_PROG_TYPES`.
        //
        // struct cgroup *bpf_cgroup_from_id(u64 cgrp_id)
        // KF_ACQUIRE | KF_RET_NULL — looks up a cgroup by id, returns
        // a fresh refcounted pointer or NULL if not found.
        "bpf_cgroup_from_id" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToCgroup)
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
                .prog_type_allowlist(&CGROUP_KFUNC_PROG_TYPES)
        }

        // struct cgroup *bpf_cgroup_acquire(struct cgroup *cgrp)
        // KF_ACQUIRE | KF_RET_NULL | KF_TRUSTED_ARGS — increments the
        // refcount on an existing cgroup pointer. Tests in
        // verifier_kfunc_prog_types.c null-check the result, so we
        // model RET_NULL (kernel may return NULL on dying cgroups).
        "bpf_cgroup_acquire" => {
            CallProto::with_args([PtrToCgroup, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToCgroup)
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
                .prog_type_allowlist(&CGROUP_KFUNC_PROG_TYPES)
        }

        // void bpf_cgroup_release(struct cgroup *cgrp)
        // KF_RELEASE — drops the refcount.
        "bpf_cgroup_release" => {
            CallProto::with_args([PtrToCgroup, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .flags(CallFlags::RELEASE)
                .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }])
                .prog_type_allowlist(&CGROUP_KFUNC_PROG_TYPES)
        }

        // struct cgroup *bpf_cgroup_ancestor(struct cgroup *cgrp, int level)
        // KF_ACQUIRE | KF_RCU | KF_RET_NULL — returns the ancestor at
        // the given level (or NULL) with a refcount the caller must
        // release.
        "bpf_cgroup_ancestor" => {
            CallProto::with_args([PtrToCgroup, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToCgroup)
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
                .prog_type_allowlist(&CGROUP_KFUNC_PROG_TYPES)
        }

        // void cgroup_rstat_updated(struct cgroup *cgrp, int cpu)
        // void cgroup_rstat_flush(struct cgroup *cgrp)
        // Plain cgroup-arg kfuncs registered as kernel symbols
        // (declared `__ksym` in selftests/cgroup_hierarchical_stats.c).
        // No flags — they neither acquire nor release; just take a
        // trusted cgroup pointer and either schedule a flush or run one.
        "cgroup_rstat_updated" => {
            CallProto::with_args([PtrToCgroup, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .prog_type_allowlist(&CGROUP_KFUNC_PROG_TYPES)
        }

        "cgroup_rstat_flush" => {
            CallProto::with_args([PtrToCgroup, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .prog_type_allowlist(&CGROUP_KFUNC_PROG_TYPES)
        }

        // struct cgroup *bpf_task_get_cgroup1(struct task_struct *task,
        //                                    int hierarchy_id)
        // KF_ACQUIRE | KF_RCU | KF_RET_NULL — looks up the v1 cgroup
        // the task is attached to in the named hierarchy. Used by the
        // bpf_cgrp_storage_* callers in cgrp_ls_*.c (recursion, tp_btf,
        // sleepable) and by test_cgroup1_hierarchy::lsm_*_run.
        "bpf_task_get_cgroup1" => {
            CallProto::with_args([PtrToTask, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToCgroup)
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
                .prog_type_allowlist(&CGROUP_KFUNC_PROG_TYPES)
        }

        // ---- Task kfuncs ----
        //
        // Mirrors the cgroup family. `RegType::PtrToTask{,OrNull}`
        // tracks the optional ref_id minted by acquire-style getters.
        // Selftest corpus exercise: local_storage.c, task_local_storage.c,
        // rcu_read_lock.c, verifier_kfunc_prog_types.c, test_snprintf.c.
        //
        // struct task_struct *bpf_get_current_task_btf(void)
        // KF_TRUSTED — returns the kernel's current-task pointer. Not
        // refcounted (the kernel guarantees liveness across the helper
        // call), so no ACQUIRE flag and ret_id stays None.
        "bpf_get_current_task_btf" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToTask)
                .prog_type_allowlist(&TASK_KFUNC_PROG_TYPES)
        }

        // struct task_struct *bpf_task_acquire(struct task_struct *p)
        // KF_ACQUIRE | KF_RET_NULL | KF_TRUSTED_ARGS — increments the
        // refcount; may return NULL on a dying task.
        "bpf_task_acquire" => {
            CallProto::with_args([PtrToTask, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToTask)
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
                .prog_type_allowlist(&TASK_KFUNC_PROG_TYPES)
        }

        // struct task_struct *bpf_task_from_pid(s32 pid)
        // KF_ACQUIRE | KF_RET_NULL — looks up a task by pid; returns
        // a fresh refcounted pointer or NULL.
        "bpf_task_from_pid" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToTask)
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
                .prog_type_allowlist(&TASK_KFUNC_PROG_TYPES)
        }

        // bpf_task_from_vpid: namespace-aware variant of from_pid. Same
        // signature shape (s32 vpid → struct task_struct *, ACQUIRE +
        // RET_NULL). Used by task_kfunc_success.c.
        "bpf_task_from_vpid" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToTask)
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
                .prog_type_allowlist(&TASK_KFUNC_PROG_TYPES)
        }

        // void bpf_task_release(struct task_struct *p)
        // KF_RELEASE — drops the refcount.
        "bpf_task_release" => {
            CallProto::with_args([PtrToTask, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .flags(CallFlags::RELEASE)
                .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }])
                .prog_type_allowlist(&TASK_KFUNC_PROG_TYPES)
        }

        // ---- vfs_accept / nested_acquire / key kfuncs ----
        //
        // Kernel types without a dedicated `RegType::PtrTo<X>` reg-type
        // specialization (`struct file`, `struct bpf_key`,
        // `struct sk_buff` from the testmod nested-acquire kfuncs)
        // funnel through `RetKind::PtrToBtfIdNamed { type_name }`, which
        // produces a `PtrToBtfId{name, TRUSTED, ref_id}`. The ref_id
        // travels on the variant for KF_ACQUIRE callers; the matching
        // KF_RELEASE consumer recovers it via `get_ref_id()` from the
        // existing `ReleaseRefFromArg` side-effect.
        //
        // struct file *bpf_get_task_exe_file(struct task_struct *task)
        // KF_ACQUIRE | KF_RET_NULL | KF_TRUSTED_ARGS — kernel registers
        // in bpf_lsm_kfunc_set; only LSM programs may call.
        "bpf_get_task_exe_file" => {
            CallProto::with_args([PtrToTask, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToBtfIdNamed { type_name: "file" })
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
                .prog_type_allowlist(&LSM_ONLY_KFUNC_PROG_TYPES)
        }

        // void bpf_put_file(struct file *file)
        // KF_RELEASE — LSM-only.
        "bpf_put_file" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .flags(CallFlags::RELEASE)
                .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }])
                .prog_type_allowlist(&LSM_ONLY_KFUNC_PROG_TYPES)
        }

        // int bpf_path_d_path(struct path *path, char *buf, u32 sz)
        // KF_TRUSTED_ARGS — fills `buf[..sz]` with the file's path; the
        // kfunc-side `bpf_d_path` analogue. Mem-size pair (R2, R3) so
        // `validate_ptr_to_uninit_mem` enforces the buffer's bounds.
        // LSM-only (kernel `bpf_lsm_kfunc_set`). R1 is strict-named
        // `struct path *` — the residual FA
        // (path_d_path_kfunc_type_mismatch) passes
        // `(struct path *)&file->f_task_work` whose corrected type
        // after the new BTF field-arithmetic is `callback_head`,
        // not `path`. PtrToBtfIdNamed catches the mismatch.
        "bpf_path_d_path" => CallProto::with_args([
            PtrToBtfIdNamed { type_name: "path" },
            PtrToUninitMem,
            ConstSize,
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::D_PATH)
        .ret(RetKind::Scalar)
        // KF_TRUSTED_ARGS — kernel rejects an untrusted `struct path *`
        // (e.g. one walked from `task->fs->root` outside an RCU CS).
        // Closes verifier_vfs_reject::path_d_path_kfunc_untrusted_*.
        .flags(CallFlags::TRUSTED_ARGS)
        .prog_type_allowlist(&LSM_ONLY_KFUNC_PROG_TYPES),

        // ---- nested-acquire test kfuncs (testmod) ----
        //
        // struct sk_buff *bpf_kfunc_nested_acquire_nonzero_offset_test(struct sk_buff_head *)
        // struct sk_buff *bpf_kfunc_nested_acquire_zero_offset_test(struct sock_common *)
        //   KF_ACQUIRE only (NOT KF_RET_NULL — kernel guarantees non-null return).
        // void bpf_kfunc_nested_release_test(struct sk_buff *)
        //   KF_RELEASE.
        "bpf_kfunc_nested_acquire_nonzero_offset_test" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToBtfIdNamed {
                    type_name: "sk_buff",
                })
                .flags(CallFlags::ACQUIRE)
        }

        "bpf_kfunc_nested_acquire_zero_offset_test" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToBtfIdNamed {
                    type_name: "sk_buff",
                })
                .flags(CallFlags::ACQUIRE)
        }

        "bpf_kfunc_nested_release_test" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .flags(CallFlags::RELEASE)
                .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }])
        }

        // ---- key kfuncs (kernel/bpf/key.c) ----
        //
        // struct bpf_key *bpf_lookup_user_key(u32 serial, u64 flags)
        // struct bpf_key *bpf_lookup_system_key(u64 id)
        //   KF_ACQUIRE | KF_RET_NULL — caller must null-check before
        //   passing to bpf_key_put.
        // void bpf_key_put(struct bpf_key *key)
        //   KF_RELEASE — rejects PtrToBtfIdOrNull at the validator
        //   (which is how we keep the upstream
        //   "user_key_reference_without_check" / "release_with_null_key_pointer"
        //   __failure tests rejected: validate_ptr_to_btf_id only accepts
        //   the non-null variant).
        "bpf_lookup_user_key" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToBtfIdNamed {
                    type_name: "bpf_key",
                })
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL | CallFlags::MIGHT_SLEEP)
        }

        "bpf_lookup_system_key" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToBtfIdNamed {
                    type_name: "bpf_key",
                })
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
        }

        "bpf_key_put" => CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
            .ret(RetKind::Void)
            .flags(CallFlags::RELEASE)
            .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }]),

        // ---- Arena kfuncs ----
        //
        //  realigns these protos with kernel semantics. The kernel
        // registers both as `KF_TRUSTED_ARGS | KF_SLEEPABLE` — NOT
        // KF_ACQUIRE / KF_RELEASE. Arena pages are reclaimed when the
        // map is destroyed, not per-alloc; consequently:
        //   - alloc without free is fine ('s UnreleasedReference
        //     check was over-approximation).
        //   - use after free is fine — freed pages simply read as zero.
        // The `ref_id` field on `RegType::PtrToArena{,OrNull}` stays
        // (the type still tracks `mem_size` for bounds checking) but is
        // always `None` because no kfunc mints one.
        //
        // void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr,
        //                                     u32 page_cnt, int node_id, u64 flags)
        // KF_RET_NULL — returns a bounded arena pointer or NULL on alloc
        // failure. R1 must be a `PtrToMapObject` whose backing map's
        // `type_ == BPF_MAP_TYPE_ARENA`. The addr-hint arg is
        // `Anything` — arena pointers come back from BTF as a kernel
        // type that we don't trace through the addr-cast.
        "bpf_arena_alloc_pages" => CallProto::with_args([
            ConstMapPtrOfType(crate::common::constants::BPF_MAP_TYPE_ARENA),
            Anything,
            Anything,
            Anything,
            Anything,
        ])
        .ret(RetKind::PtrToArenaFromArg { page_cnt_arg: 2 })
        .flags(CallFlags::RET_NULL),

        // void bpf_arena_free_pages(void *map, void __arena *ptr, u32 page_cnt)
        // No KF flags — verifier-side this is a no-op shape check. R2
        // must still be a non-null `PtrToArena` (validates the arg is
        // really an arena pointer), and R1 must be an arena map. The
        // pointer is NOT invalidated — kernel allows reads after free
        // (they return zero).
        "bpf_arena_free_pages" => CallProto::with_args([
            ConstMapPtrOfType(crate::common::constants::BPF_MAP_TYPE_ARENA),
            PtrToArena,
            Anything,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void),

        // ---- Owned-kptr alloc / drop / refcount ----
        //
        // void *bpf_obj_new_impl(u64 local_type_id, void *meta__ign)
        // KF_ACQUIRE | KF_RET_NULL — heap-allocates a refcounted kernel
        // object of the BTF-described type. The meta pointer is compiler-
        // generated and not modeled here (Anything). Returns NULL on
        // alloc failure; program must null-check before using.
        "bpf_obj_new_impl" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToOwnedKptr)
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
        }

        // void bpf_obj_drop_impl(void *kptr, void *meta__ign)
        // KF_RELEASE — drops the refcount. R1 must be a non-null,
        // ref-tracked PtrToOwnedKptr; ReleaseRefFromArg invalidates the
        // ref everywhere it's still aliased.
        "bpf_obj_drop_impl" => {
            CallProto::with_args([PtrToOwnedKptr, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .flags(CallFlags::RELEASE)
                .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }])
        }

        // void *bpf_percpu_obj_new_impl(u64 local_type_id, void *meta__ign)
        // KF_ACQUIRE | KF_RET_NULL — heap-allocates a percpu object.
        // Kernel returns `PTR_TO_BTF_ID | MEM_ALLOC | MEM_PERCPU |
        // PTR_TRUSTED | MAYBE_NULL`. We type R0 in the kfunc.rs post-
        // call hook (resolves local_type_id → struct name from R1's
        // const value, mints PtrToBtfIdOrNull with PERCPU+MEM_ALLOC).
        // CallProto here just clears the dispatch-time "unknown kfunc"
        // rejection.
        "bpf_percpu_obj_new_impl" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
        }

        // void bpf_percpu_obj_drop_impl(void *kptr, void *meta__ign)
        // KF_RELEASE — drops the percpu allocation. R1 is a percpu
        // BTF-id pointer (acquired via bpf_percpu_obj_new or
        // bpf_kptr_xchg out of a __percpu_kptr field). Validator gates
        // on PtrToBtfId with PERCPU + ref_id; ReleaseRefFromArg
        // invalidates aliases.
        "bpf_percpu_obj_drop_impl" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .flags(CallFlags::RELEASE)
                .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }])
        }

        // void *bpf_refcount_acquire_impl(void *kptr, void *meta__ign)
        // KF_ACQUIRE | KF_RET_NULL — bumps the refcount and returns a
        // fresh ref to the same object. The input ref stays valid (no
        // RELEASE flag); the new ref must be independently dropped or
        // pushed into a container.
        // Kernel commit 7793fc3d (v6.13) dropped KF_RET_NULL from
        // bpf_refcount_acquire_impl: the input ref already guarantees
        // refcount > 0, so the bumped result cannot be NULL. Programs
        // ≥ v6.13 (incl. refcounted_kptr.c) skip the null check.
        "bpf_refcount_acquire_impl" => {
            CallProto::with_args([PtrToOwnedKptr, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToOwnedKptr)
                .flags(CallFlags::ACQUIRE)
        }

        // ---- List + rbtree kfuncs ----
        //
        // int bpf_list_push_front_impl(struct bpf_list_head *head,
        //                              struct bpf_list_node *node,
        //                              void *meta__ign, u64 off__ign)
        // KF_RELEASE on the node — transfers ownership into the list.
        // KF_LOCK_HELD: must be called under a spin_lock (real kernel
        // requires the lock that protects this list head; lite scope
        // accepts any held lock). R1 must point at a SpecialField{ListHead}
        // inside a map value.
        "bpf_list_push_front_impl" => CallProto::with_args([
            MapValueSpecial {
                kind: SpecialFieldKind::ListHead,
            },
            PtrToOwnedKptr,
            Anything,
            Anything,
            DontCare,
        ])
        .ret(RetKind::Void)
        .flags(CallFlags::RELEASE | CallFlags::RELEASE_NON_OWN | CallFlags::SPIN_LOCK_HELD)
        .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 1 }]),

        // struct bpf_list_node *bpf_list_pop_front(struct bpf_list_head *head)
        // KF_ACQUIRE | KF_RET_NULL | KF_LOCK_HELD — pops a node out of
        // the list and hands ownership to the caller. NULL on empty list.
        "bpf_list_pop_front" => CallProto::with_args([
            MapValueSpecial {
                kind: SpecialFieldKind::ListHead,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::PtrToOwnedKptr)
        .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL | CallFlags::SPIN_LOCK_HELD),

        // bpf_list_push_back_impl / bpf_list_pop_back — symmetric
        // back-of-list variants. Same ownership / lock contracts as
        // their _front counterparts above.
        "bpf_list_push_back_impl" => CallProto::with_args([
            MapValueSpecial {
                kind: SpecialFieldKind::ListHead,
            },
            PtrToOwnedKptr,
            Anything,
            Anything,
            DontCare,
        ])
        .ret(RetKind::Void)
        .flags(CallFlags::RELEASE | CallFlags::RELEASE_NON_OWN | CallFlags::SPIN_LOCK_HELD)
        .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 1 }]),

        "bpf_list_pop_back" => CallProto::with_args([
            MapValueSpecial {
                kind: SpecialFieldKind::ListHead,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::PtrToOwnedKptr)
        .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL | CallFlags::SPIN_LOCK_HELD),

        // int bpf_rbtree_add_impl(struct bpf_rb_root *root,
        //                         struct bpf_rb_node *node,
        //                         bool (*less)(struct bpf_rb_node *,
        //                                      const struct bpf_rb_node *),
        //                         void *meta__ign, u64 off__ign)
        // KF_RELEASE on the node + KF_LOCK_HELD. Lite scope: the `less`
        // callback (R3) is accepted as Anything — we don't walk into the
        // cb subprog for ordering-correctness checks. Tech-debt: future
        // precision should validate it as `PtrToCallback` and explore.
        // struct bpf_rb_node *bpf_rbtree_first(struct bpf_rb_root *root)
        // KF_RET_NULL | KF_LOCK_HELD — peek at the leftmost node.
        // Return is a *non-owning* ref (no KF_ACQUIRE); the caller may
        // dereference it under the lock but cannot drop it. We model
        // the result as a `PtrToOwnedKptr` without `ref_id` (so any
        // attempt to release it is rejected by the
        // `ReleaseRefFromArg` precondition gate which demands a
        // present `ref_id`). After bpf_spin_unlock, non-owning refs
        // are invalidated by `state.invalidate_non_owning_refs()`.
        "bpf_rbtree_first" => CallProto::with_args([
            MapValueSpecial {
                kind: SpecialFieldKind::RbRoot,
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::PtrToOwnedKptr)
        .flags(CallFlags::RET_NULL | CallFlags::SPIN_LOCK_HELD),

        // struct bpf_rb_node *bpf_rbtree_remove(struct bpf_rb_root *root,
        //                                       struct bpf_rb_node *node)
        // KF_ACQUIRE | KF_RET_NULL | KF_LOCK_HELD — pull `node` out of
        // the tree, hand the caller a fresh owning ref. The `node`
        // arg must be a non-owning rb_node ref already in the tree
        // (kernel rejects "rbtree_remove node input must be
        // non-owning ref"); lite scope accepts any `PtrToOwnedKptr`.
        "bpf_rbtree_remove" => CallProto::with_args([
            MapValueSpecial {
                kind: SpecialFieldKind::RbRoot,
            },
            PtrToOwnedKptr,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::PtrToOwnedKptr)
        .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL | CallFlags::SPIN_LOCK_HELD),

        "bpf_rbtree_add_impl" => CallProto::with_args([
            MapValueSpecial {
                kind: SpecialFieldKind::RbRoot,
            },
            PtrToOwnedKptr,
            Anything,
            Anything,
            DontCare,
        ])
        .ret(RetKind::Void)
        .flags(CallFlags::RELEASE | CallFlags::RELEASE_NON_OWN | CallFlags::SPIN_LOCK_HELD)
        .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 1 }]),

        // ---- bpf_wq family (kernel v6.10) ----
        //
        // Async work-queue: same shape as bpf_timer but cb runs in a
        // workqueue context. Three kfuncs:
        //
        //   int bpf_wq_init(struct bpf_wq *wq, struct bpf_map *map, u64 flags)
        //   int bpf_wq_set_callback_impl(struct bpf_wq *wq,
        //                                int (*callback)(void*,int*,void*),
        //                                u64 flags__ign,
        //                                void *aux__ign)
        //   int bpf_wq_start(struct bpf_wq *wq, u64 flags)
        //
        // R1 is `&map_value->wq` (PtrToMapValue carrying owning map_idx),
        // validated via MapValueSpecial(Wq). bpf_wq_init has a kernel
        // cross-arg check that R1's owning map matches R2's map_uid; we
        // mirror via a coarse map_idx-equality check in transfer.rs's
        // bpf_wq_init arm (keeps wq_failures::test_wq_init_wrong_map
        // correctly rejecting). bpf_wq_set_callback_impl is routed
        // through a kfunc callback-fork in transfer.rs (the cb runs
        // async, so registration requires no held locks / unreleased
        // refs — same async-constraint as BPF_TIMER_SET_CALLBACK).
        "bpf_wq_init" => CallProto::with_args([
            MapValueSpecial {
                kind: SpecialFieldKind::Wq,
            }, // R1: &wq field
            ConstMapPtr, // R2: owning map
            Anything,    // R3: flags
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        "bpf_wq_set_callback_impl" => CallProto::with_args([
            MapValueSpecial {
                kind: SpecialFieldKind::Wq,
            }, // R1: &wq field
            PtrToCallback, // R2: callback subprog
            Anything,      // R3: flags__ign
            DontCare,      // R4: aux__ign
            DontCare,
        ])
        .ret(RetKind::Scalar),

        "bpf_wq_start" => CallProto::with_args([
            MapValueSpecial {
                kind: SpecialFieldKind::Wq,
            }, // R1: &wq field
            Anything, // R2: flags
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- kernel-exported TCP CC helpers ----
        //
        // bpf_dctcp.c and bpf_cubic.c reach into the kernel's TCP
        // congestion-control library via these ksyms. Clang emits each
        // as a `BPF_PSEUDO_KFUNC_CALL`; without protos here, our kfunc
        // dispatcher rejects with `UnsupportedModernFeature`.
        //
        // All four take a sock/tcp_sock pointer (which our struct_ops
        // entry-state plumbing types as PtrToBtfId{unknown}) plus
        // scalars; three return void, one returns u32. We model the
        // pointer args as `PtrToBtfId` (matches the trusted-pointer
        // shape) and let the verifier's permissive "unknown" type_name
        // path handle access typing.
        //
        //   void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 acked)
        //   void tcp_slow_start    (struct tcp_sock *tp, u32 acked)
        //   void tcp_cong_avoid_ai (struct tcp_sock *tp, u32 w, u32 acked)
        //   u32  tcp_reno_undo_cwnd(struct sock *sk)
        "tcp_reno_cong_avoid" => {
            CallProto::with_args([PtrToBtfId, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::Void)
        }

        "tcp_slow_start" => {
            CallProto::with_args([PtrToBtfId, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }

        "tcp_cong_avoid_ai" => {
            CallProto::with_args([PtrToBtfId, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::Void)
        }

        "tcp_reno_undo_cwnd" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- TCP CC algorithm ksyms (BBR / DCTCP / CUBIC) ----
        //
        // tcp_ca_kfunc.c and bpf_cc_cubic.c reach into the kernel's
        // bbr / dctcp / cubictcp implementations via __ksym externs.
        // Same shape as the tcp_reno_* family above: each takes a
        // sock pointer (typed PtrToBtfId by struct_ops entry-state
        // plumbing) plus scalars; void or u32 return. Pure additive
        // registration — no acquire/release, no allowlist.
        //
        //   void bbr_init(struct sock *sk)
        //   void bbr_main(struct sock *sk, u32 ack, int flag,
        //                 const struct rate_sample *rs)
        //   u32  bbr_sndbuf_expand(struct sock *sk)
        //   u32  bbr_undo_cwnd(struct sock *sk)
        //   void bbr_cwnd_event(struct sock *sk, enum tcp_ca_event event)
        //   u32  bbr_ssthresh(struct sock *sk)
        //   u32  bbr_min_tso_segs(struct sock *sk)
        //   void bbr_set_state(struct sock *sk, u8 new_state)
        "bbr_init" => CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
            .ret(RetKind::Void),
        "bbr_main" => CallProto::with_args([PtrToBtfId, Anything, Anything, Anything, DontCare])
            .ret(RetKind::Void),
        "bbr_sndbuf_expand" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bbr_undo_cwnd" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bbr_cwnd_event" => {
            CallProto::with_args([PtrToBtfId, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "bbr_ssthresh" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bbr_min_tso_segs" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bbr_set_state" => {
            CallProto::with_args([PtrToBtfId, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }

        //   void dctcp_init(struct sock *sk)
        //   void dctcp_update_alpha(struct sock *sk, u32 flags)
        //   void dctcp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
        //   u32  dctcp_ssthresh(struct sock *sk)
        //   u32  dctcp_cwnd_undo(struct sock *sk)
        //   void dctcp_state(struct sock *sk, u8 new_state)
        "dctcp_init" => CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
            .ret(RetKind::Void),
        "dctcp_update_alpha" => {
            CallProto::with_args([PtrToBtfId, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "dctcp_cwnd_event" => {
            CallProto::with_args([PtrToBtfId, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "dctcp_ssthresh" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "dctcp_cwnd_undo" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "dctcp_state" => CallProto::with_args([PtrToBtfId, Anything, DontCare, DontCare, DontCare])
            .ret(RetKind::Void),

        //   void cubictcp_init(struct sock *sk)
        //   u32  cubictcp_recalc_ssthresh(struct sock *sk)
        //   void cubictcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
        //   void cubictcp_state(struct sock *sk, u8 new_state)
        //   void cubictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
        //   void cubictcp_acked(struct sock *sk, const struct ack_sample *sample)
        "cubictcp_init" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "cubictcp_recalc_ssthresh" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "cubictcp_cong_avoid" => {
            CallProto::with_args([PtrToBtfId, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "cubictcp_state" => {
            CallProto::with_args([PtrToBtfId, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "cubictcp_cwnd_event" => {
            CallProto::with_args([PtrToBtfId, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "cubictcp_acked" => {
            CallProto::with_args([PtrToBtfId, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }

        // ---- testmod sock-addr-syscall kfuncs (sock_addr_kern.c) ----
        //
        // Test kfuncs registered by bpf_testmod for the
        // sock_addr/syscall integration coverage. All called from
        // SEC("syscall") programs with a pointer to a per-test args
        // struct (`init_sock_args` / `addr_args` / `sendmsg_args`)
        // sitting on the syscall caller's input buffer; void or int
        // return. Pure additive — no acquire/release.
        //
        //   int  bpf_kfunc_init_sock(struct init_sock_args *args)
        //   void bpf_kfunc_close_sock(void)
        //   int  bpf_kfunc_call_kernel_connect(struct addr_args *args)
        //   int  bpf_kfunc_call_kernel_bind(struct addr_args *args)
        //   int  bpf_kfunc_call_kernel_listen(void)
        //   int  bpf_kfunc_call_kernel_sendmsg(struct sendmsg_args *args)
        //   int  bpf_kfunc_call_sock_sendmsg(struct sendmsg_args *args)
        //   int  bpf_kfunc_call_kernel_getsockname(struct addr_args *args)
        //   int  bpf_kfunc_call_kernel_getpeername(struct addr_args *args)
        "bpf_kfunc_init_sock" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_kfunc_close_sock" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "bpf_kfunc_call_kernel_connect" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_kfunc_call_kernel_bind" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_kfunc_call_kernel_listen" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_kfunc_call_kernel_sendmsg" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_kfunc_call_sock_sendmsg" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_kfunc_call_kernel_getsockname" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_kfunc_call_kernel_getpeername" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- testmod ref-tracked kfuncs (kfunc_call_test.c, map_kptr.c,
        //      jit_probe_mem.c, local_kptr_stash.c) ----
        //
        // struct prog_test_ref_kfunc *bpf_kfunc_call_test_acquire(unsigned long *)
        //   KF_ACQUIRE | KF_RET_NULL — mints a fresh refcounted pointer.
        // void bpf_kfunc_call_test_release(struct prog_test_ref_kfunc *p)
        //   KF_RELEASE — drops the ref minted by _acquire.
        // void bpf_kfunc_call_test_ref(struct prog_test_ref_kfunc *p)
        //   No flags — non-acquire/release passthrough; just validates a
        //   trusted ref arg.
        //
        // Returning PtrToBtfIdNamed{prog_test_ref_kfunc} keeps the matching
        // __failure siblings rejecting via the existing trusted-arg /
        // ref-id machinery. The bounded-mem-returning siblings
        // (bpf_kfunc_call_test_get_rdonly_mem / _get_rdwr_mem) are NOT
        // registered: they would need PtrToAllocMemFromArg + rdonly
        // tracking + ref-id propagation onto the returned mem to keep
        // the matching __failure tests in kfunc_call_fail.c rejecting.
        "bpf_kfunc_call_test_acquire" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToBtfIdNamed {
                    type_name: "prog_test_ref_kfunc",
                })
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
        }

        "bpf_kfunc_call_test_release" => CallProto::with_args([
            PtrToBtfIdNamed {
                type_name: "prog_test_ref_kfunc",
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .flags(CallFlags::RELEASE)
        .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }]),

        "bpf_kfunc_call_test_ref" => CallProto::with_args([
            PtrToBtfIdNamed {
                type_name: "prog_test_ref_kfunc",
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void),

        // int *bpf_kfunc_call_test_get_rdwr_mem(struct prog_test_ref_kfunc *p,
        //                                       const int rdwr_buf_size)
        // int *bpf_kfunc_call_test_get_rdonly_mem(struct prog_test_ref_kfunc *p,
        //                                         const int rdonly_buf_size)
        // KF_RET_NULL on both. Returns a bounded mem region whose size
        // is the value of R2 (a `const int`). Lite scope: model both with
        // `RetKind::PtrToAllocMemFromArg { size_arg: 1 }` — no rdonly /
        // ref-id-on-mem distinction. The matching `kfunc_call_fail.c`
        // siblings (rdonly-store, use-after-free, oob, non-const-size)
        // are upstream-ACCEPT in the v6.15 baseline (skel `?tc`-gated),
        // so the absent rdonly enforcement and ref-id propagation don't
        // surface FAs.
        "bpf_kfunc_call_test_get_rdwr_mem" => CallProto::with_args([
            PtrToBtfIdNamed {
                type_name: "prog_test_ref_kfunc",
            },
            Anything,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::PtrToAllocMemFromArg { size_arg: 1 })
        .flags(CallFlags::RET_NULL),

        "bpf_kfunc_call_test_get_rdonly_mem" => CallProto::with_args([
            PtrToBtfIdNamed {
                type_name: "prog_test_ref_kfunc",
            },
            Anything,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::PtrToAllocMemFromArg { size_arg: 1 })
        .flags(CallFlags::RET_NULL),

        // struct bpf_testmod_ctx *bpf_testmod_ctx_create(int *err)
        //   KF_ACQUIRE | KF_RET_NULL.
        // void bpf_testmod_ctx_release(struct bpf_testmod_ctx *ctx)
        //   KF_RELEASE.
        "bpf_testmod_ctx_create" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToBtfIdNamed {
                    type_name: "bpf_testmod_ctx",
                })
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
        }

        "bpf_testmod_ctx_release" => CallProto::with_args([
            PtrToBtfIdNamed {
                type_name: "bpf_testmod_ctx",
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .flags(CallFlags::RELEASE)
        .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }]),

        // ---- testmod basic test kfuncs (kfunc_call_test.c) ----
        //
        // Scalar-only and pointer helpers (companion to the ref-tracked
        // family above).
        //
        // bpf_kfunc_call_test_pass_ctx takes `struct __sk_buff *skb`
        // — modeled as PtrToCtx so the matching __failure sibling
        // `kfunc_call_test_pointer_arg_type_mismatch` (passes literal
        // `(void *)10`) keeps rejecting. The mem_len_* kfuncs take a
        // (mem, len) pair — wired up via MemSizePair so the
        // out-of-bounds `kfunc_syscall_test_fail` sibling rejects on
        // size validation.
        //
        //   __u64 bpf_kfunc_call_test1(struct sock *sk, u32, u64, u32, u64)
        //   int   bpf_kfunc_call_test2(struct sock *sk, u32, u32)
        //   long  bpf_kfunc_call_test4(s8, s16, int, long)
        //   void  bpf_kfunc_call_test_pass_ctx(struct __sk_buff *skb)
        //   void  bpf_kfunc_call_test_pass1(struct prog_test_pass1 *p)
        //   void  bpf_kfunc_call_test_pass2(struct prog_test_pass2 *p)
        //   void  bpf_kfunc_call_test_mem_len_pass1(void *mem, int len)
        //   void  bpf_kfunc_call_test_mem_len_fail2(__u64 *mem, int len)
        //   u32   bpf_kfunc_call_test_static_unused_arg(u32 arg, u32 unused)
        "bpf_kfunc_call_test1" => {
            CallProto::with_args([Anything, Anything, Anything, Anything, Anything])
                .ret(RetKind::Scalar)
        }
        // struct sock *bpf_kfunc_call_test3(struct sock *sk) — passthrough
        // (returns the same sock). No KF_ACQUIRE / KF_RET_NULL flags;
        // caller dereferences the returned sock directly without a null
        // check (`bpf_kfunc_call_test3(sk)->__sk_common.skc_state`).
        "bpf_kfunc_call_test3" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToBtfIdNamed { type_name: "sock" })
        }
        "bpf_kfunc_call_test2" => {
            CallProto::with_args([Anything, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_kfunc_call_test4" => {
            CallProto::with_args([Anything, Anything, Anything, Anything, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_kfunc_call_test_pass_ctx" => {
            CallProto::with_args([PtrToCtx, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "bpf_kfunc_call_test_pass1" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "bpf_kfunc_call_test_pass2" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "bpf_kfunc_call_test_mem_len_pass1" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "bpf_kfunc_call_test_mem_len_fail2" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "bpf_kfunc_call_test_static_unused_arg" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- bpf_kfunc_common_test (testmod, no-op trace anchor) ----
        // `void bpf_kfunc_common_test(void)`. Registered from
        // bpf_testmod_kfunc.h; used by missed_kprobe.c, missed_kprobe_recursion.c,
        // and the wq.c sleepable callback variants as a trace-anchor target
        // (test driver puts a kprobe on this function to count invocations).
        // Trivially additive: no args, no side effects.
        "bpf_kfunc_common_test" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }

        // ---- bpf_kfunc_call_test_sleepable (testmod, KF_SLEEPABLE) ----
        // `void bpf_kfunc_call_test_sleepable(void)`. Used by wq.c's
        // sleepable cb (`wq_cb_sleepable`) to mark the cb path as
        // sleepable for the test driver. KF_SLEEPABLE is a runtime
        // gate (kernel rejects non-sleepable callers); we don't enforce
        // it here because the wq cb's sleepable-ness is set via the wq
        // setup, not visible at the call site.
        "bpf_kfunc_call_test_sleepable" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }

        // ---- bpf_kfunc_call_test_destructive (testmod) ----
        // `void bpf_kfunc_call_test_destructive(void)` — KF_DESTRUCTIVE
        // (CAP_SYS_BOOT-gated runtime check; verifier just needs the
        // proto). Used by kfunc_call_destructive.c.
        "bpf_kfunc_call_test_destructive" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }

        // ---- bpf_testmod_ops3_call_test_{1,2} (testmod struct_ops3) ----
        // `void bpf_testmod_ops3_call_test_N(void)` — used by struct_ops
        // private-stack tests (struct_ops_private_stack.c,
        // struct_ops_private_stack_recur.c) to thunk into ops3 vtable
        // methods. No args, no side effects.
        "bpf_testmod_ops3_call_test_1" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }

        "bpf_testmod_ops3_call_test_2" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }

        // ---- bpf_xdp_flow_lookup (nf_flow_table xdp helper) ----
        // `struct flow_offload_tuple_rhash *bpf_xdp_flow_lookup(
        //      struct xdp_md *, struct bpf_fib_lookup *,
        //      struct bpf_flowtable_opts___local *, u32)`
        // — used by xdp_flowtable.c. Caller only null-checks the
        // returned pointer; Scalar return matches the same pattern as
        // bpf_get_kmem_cache.
        "bpf_xdp_flow_lookup" => {
            CallProto::with_args([PtrToCtx, Anything, Anything, Anything, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- bpf_map_sum_elem_count (map introspection) ----
        // `__s64 bpf_map_sum_elem_count(const struct bpf_map *map)` —
        // sums per-cpu counters; runtime helper used by
        // map_percpu_stats.c (iter/bpf_map: ctx->map yields
        // PtrToBtfId{bpf_map}, not ConstMapPtr) and map_ptr_kern.c
        // (subprog arg). Anything matches the kernel acceptance of
        // either &literal_map or a typed bpf_map* from iter ctx; the
        // kernel runtime gates the call by BTF type-id check.
        "bpf_map_sum_elem_count" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- testmod struct_ops prologue/epilogue test kfuncs ----
        // Used by pro_epilogue.c, pro_epilogue_goto_start.c,
        // epilogue_exit.c (`syscall_*` SEC programs that thunk into
        // the struct_ops test infrastructure). Each takes
        // `struct st_ops_args *args` and returns int.
        //
        //   int bpf_kfunc_st_ops_test_prologue(struct st_ops_args *)
        //   int bpf_kfunc_st_ops_test_epilogue(struct st_ops_args *)
        //   int bpf_kfunc_st_ops_test_pro_epilogue(struct st_ops_args *)
        "bpf_kfunc_st_ops_test_prologue" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_kfunc_st_ops_test_epilogue" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_kfunc_st_ops_test_pro_epilogue" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- testmod cross-module ordering test kfuncs ----
        // kfunc_module_order.c: two kfuncs registered from different
        // modules to exercise cross-module dispatch. No args.
        //
        //   int bpf_test_modorder_retx(void)  // returns 'x'
        //   int bpf_test_modorder_rety(void)  // returns 'y'
        "bpf_test_modorder_retx" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_test_modorder_rety" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- bpf_send_signal_task ----
        // test_send_signal_kern.c: targeted signal-delivery kfunc.
        //   int bpf_send_signal_task(struct task_struct *task,
        //                            int sig, enum pid_type type,
        //                            u64 value)
        // task arg is Anything to accept the PtrToTask result of
        // bpf_task_from_pid (and any other future task-pointer reg
        // type) without re-implementing per-arg trust gates.
        "bpf_send_signal_task" => {
            CallProto::with_args([Anything, Anything, Anything, Anything, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- kprobe/uprobe session kfuncs ----
        // bpf_session_cookie() returns `__u64 *` — a pointer to an
        // 8-byte per-call stash slot the program reads/writes via
        // *cookie. Modeled with PtrToAllocMem{mem_size=8} so the
        // verifier accepts the 8-byte deref pattern. (Programs may
        // load OR store through the returned pointer.)
        // bpf_session_is_return() returns a 0/1 flag for return-probe
        // disambiguation. Used in kprobe_multi_session_cookie.c,
        // uprobe_multi_session_cookie.c, uprobe_multi_session.c.
        "bpf_session_cookie" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToAllocMem { mem_size: 8 })
        }
        "bpf_session_is_return" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- testmod nullable-dynptr arg test ----
        // bpf_kfunc_dynptr_test(struct bpf_dynptr *, struct bpf_dynptr *__nullable)
        // Used by test_kfunc_param_nullable.c. Both args are dynptrs;
        // the second is nullable. Modeled with DynptrArg consumers
        // (initialized, rdwr or rdonly) so the existing dynptr arg
        // validator handles slot-state checks. The nullable second
        // arg uses Anything to accept literal NULL plus init dynptrs.
        "bpf_kfunc_dynptr_test" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            },
            Anything,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void),

        // ---- LSM xattr kfuncs ----
        // Used by test_get_xattr.c, test_set_remove_xattr.c (lsm.s/*
        // SEC). Each takes a kernel object pointer + name string +
        // optional value dynptr and returns int. Args are Anything
        // since the file/dentry pointers come from BPF_PROG entry
        // typing as PtrToBtfId{file/dentry} which we don't strictly
        // gate.
        //
        //   int bpf_get_file_xattr(struct file *, const char *,
        //                          struct bpf_dynptr *value)
        //   int bpf_get_dentry_xattr(struct dentry *, const char *,
        //                            struct bpf_dynptr *value)
        //   int bpf_set_dentry_xattr(struct dentry *, const char *,
        //                            struct bpf_dynptr *value, int flags)
        //   int bpf_remove_dentry_xattr(struct dentry *, const char *)
        "bpf_get_file_xattr" => {
            CallProto::with_args([Anything, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_get_dentry_xattr" => {
            CallProto::with_args([Anything, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_set_dentry_xattr" => {
            CallProto::with_args([Anything, Anything, Anything, Anything, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_remove_dentry_xattr" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        // Locked variants (test_set_remove_xattr.c additionally
        // exercises these; kernel registers them separately).
        "bpf_set_dentry_xattr_locked" => {
            CallProto::with_args([Anything, Anything, Anything, Anything, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_remove_dentry_xattr_locked" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- FOU/GUE tunnel encap kfuncs (test_tunnel_kern.c) ----
        //   int bpf_skb_set_fou_encap(struct __sk_buff *, struct bpf_fou_encap *, int)
        //   int bpf_skb_get_fou_encap(struct __sk_buff *, struct bpf_fou_encap *)
        "bpf_skb_set_fou_encap" => {
            CallProto::with_args([PtrToCtx, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_skb_get_fou_encap" => {
            CallProto::with_args([PtrToCtx, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- Crypto kfuncs (crypto_basic.c, crypto_bench.c, crypto_sanity.c) ----
        //
        // struct bpf_crypto_ctx *bpf_crypto_ctx_create(const struct bpf_crypto_params *,
        //                                              u32 params__sz, int *err)
        //   KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE.
        // struct bpf_crypto_ctx *bpf_crypto_ctx_acquire(struct bpf_crypto_ctx *ctx)
        //   KF_ACQUIRE | KF_RET_NULL.
        // void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx)
        //   KF_RELEASE.
        // int bpf_crypto_encrypt/_decrypt(struct bpf_crypto_ctx *ctx,
        //                                  const struct bpf_dynptr *src,
        //                                  const struct bpf_dynptr *dst,
        //                                  const struct bpf_dynptr *iv)
        //   No flags; the iv arg is __nullable.
        "bpf_crypto_ctx_create" => {
            CallProto::with_args([Anything, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::PtrToBtfIdNamed {
                    type_name: "bpf_crypto_ctx",
                })
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL | CallFlags::MIGHT_SLEEP)
        }

        "bpf_crypto_ctx_acquire" => CallProto::with_args([
            PtrToBtfIdNamed {
                type_name: "bpf_crypto_ctx",
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::PtrToBtfIdNamed {
            type_name: "bpf_crypto_ctx",
        })
        .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL),

        "bpf_crypto_ctx_release" => CallProto::with_args([
            PtrToBtfIdNamed {
                type_name: "bpf_crypto_ctx",
            },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Void)
        .flags(CallFlags::RELEASE)
        .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }]),

        "bpf_crypto_encrypt" => CallProto::with_args([
            PtrToBtfIdNamed {
                type_name: "bpf_crypto_ctx",
            },
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            },
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            },
            Anything,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        "bpf_crypto_decrypt" => CallProto::with_args([
            PtrToBtfIdNamed {
                type_name: "bpf_crypto_ctx",
            },
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            },
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            },
            Anything,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- TCP raw syncookie kfuncs (xdp_synproxy_kern.c,
        //      test_tcp_custom_syncookie.c) ----
        //
        // u64 bpf_tcp_raw_gen_syncookie_ipv4(struct iphdr *, struct tcphdr *, u32)
        // u64 bpf_tcp_raw_gen_syncookie_ipv6(struct ipv6hdr *, struct tcphdr *, u32)
        // int bpf_tcp_raw_check_syncookie_ipv4(struct iphdr *, struct tcphdr *)
        // int bpf_tcp_raw_check_syncookie_ipv6(struct ipv6hdr *, struct tcphdr *)
        //   No flags. Operate on packet-derived header pointers.
        // int bpf_sk_assign_tcp_reqsk(struct __sk_buff *, struct sock *,
        //                              struct bpf_tcp_req_attrs *, u32)
        //   No flags. Used by test_tcp_custom_syncookie to install the
        //   custom syncookie's request_sock onto the skb.
        "bpf_tcp_raw_gen_syncookie_ipv4" => {
            CallProto::with_args([Anything, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        "bpf_tcp_raw_gen_syncookie_ipv6" => {
            CallProto::with_args([Anything, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        "bpf_tcp_raw_check_syncookie_ipv4" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        "bpf_tcp_raw_check_syncookie_ipv6" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        "bpf_sk_assign_tcp_reqsk" => {
            CallProto::with_args([PtrToCtx, Anything, Anything, Anything, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- Conntrack kfuncs (test_bpf_nf.c, xdp_synproxy_kern.c) ----
        //
        // bpf_xdp_ct_lookup / bpf_xdp_ct_alloc / bpf_skb_ct_lookup / bpf_skb_ct_alloc:
        //   KF_ACQUIRE | KF_RET_NULL — return a refcounted nf_conn pointer.
        //   Args: ctx, sock_tuple, len, opts, opts_len.
        // bpf_ct_insert_entry:
        //   KF_ACQUIRE | KF_RET_NULL | KF_RELEASE on the input — confirms an
        //   allocated entry; consumes the alloc-time ref and returns a fresh
        //   inserted ref.
        // bpf_ct_release:
        //   KF_RELEASE — drops the refcount.
        // bpf_ct_set_timeout / bpf_ct_change_timeout / bpf_ct_set_status /
        // bpf_ct_change_status / bpf_ct_set_nat_info:
        //   No flags — non-acquire/release setters on a trusted nf_conn.
        "bpf_xdp_ct_lookup" => {
            CallProto::with_args([PtrToCtx, Anything, Anything, Anything, Anything])
                .ret(RetKind::PtrToBtfIdNamed {
                    type_name: "nf_conn",
                })
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
        }

        "bpf_xdp_ct_alloc" => {
            CallProto::with_args([PtrToCtx, Anything, Anything, Anything, Anything])
                .ret(RetKind::PtrToBtfIdNamed {
                    type_name: "nf_conn___init",
                })
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
        }

        "bpf_skb_ct_lookup" => {
            CallProto::with_args([PtrToCtx, Anything, Anything, Anything, Anything])
                .ret(RetKind::PtrToBtfIdNamed {
                    type_name: "nf_conn",
                })
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
        }

        "bpf_skb_ct_alloc" => {
            CallProto::with_args([PtrToCtx, Anything, Anything, Anything, Anything])
                .ret(RetKind::PtrToBtfIdNamed {
                    type_name: "nf_conn___init",
                })
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
        }

        // bpf_ct_insert_entry releases the input nf_conn___init ref and
        // returns a fresh nf_conn ref (transition from "uninitialized"
        // construction state to "live in conntrack table"). Modeled as
        // RELEASE+ACQUIRE+RET_NULL with ReleaseRefFromArg on R1.
        "bpf_ct_insert_entry" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToBtfIdNamed {
                    type_name: "nf_conn",
                })
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL | CallFlags::RELEASE)
                .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }])
        }

        "bpf_ct_release" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .flags(CallFlags::RELEASE)
                .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }])
        }

        "bpf_ct_set_timeout" => {
            CallProto::with_args([PtrToBtfId, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }

        "bpf_ct_change_timeout" => {
            CallProto::with_args([PtrToBtfId, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        "bpf_ct_set_status" => {
            CallProto::with_args([PtrToBtfId, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        "bpf_ct_change_status" => {
            CallProto::with_args([PtrToBtfId, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        "bpf_ct_set_nat_info" => {
            CallProto::with_args([PtrToBtfId, Anything, Anything, Anything, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- xfrm state kfuncs (test_tunnel_kern.c xfrm_get_state_xdp) ----
        // struct xfrm_state *bpf_xdp_get_xfrm_state(struct xdp_md *ctx,
        //                                           struct bpf_xfrm_state_opts *opts,
        //                                           u32 opts__sz)
        //   KF_ACQUIRE | KF_RET_NULL — looks up an xfrm state by SPI/daddr.
        // void bpf_xdp_xfrm_state_release(struct xfrm_state *x)
        //   KF_RELEASE — drops the ref minted by bpf_xdp_get_xfrm_state.
        "bpf_xdp_get_xfrm_state" => {
            CallProto::with_args([PtrToCtx, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::PtrToBtfIdNamed {
                    type_name: "xfrm_state",
                })
                .flags(CallFlags::ACQUIRE | CallFlags::RET_NULL)
        }

        "bpf_xdp_xfrm_state_release" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .flags(CallFlags::RELEASE)
                .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }])
        }

        // ---- xfrm info kfuncs (xfrm_info.c) ----
        //   int bpf_skb_set_xfrm_info(struct __sk_buff *, const struct bpf_xfrm_info *)
        //   int bpf_skb_get_xfrm_info(struct __sk_buff *, struct bpf_xfrm_info *)
        "bpf_skb_set_xfrm_info" => {
            CallProto::with_args([PtrToCtx, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        "bpf_skb_get_xfrm_info" => {
            CallProto::with_args([PtrToCtx, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- bpf_task_under_cgroup ----
        // long bpf_task_under_cgroup(struct task_struct *task,
        //                            struct cgroup *ancestor)
        // Used by test_task_under_cgroup.c. task / ancestor are
        // Anything to accept PtrToTask/PtrToCgroup minted by the
        // existing acquire kfuncs.
        "bpf_task_under_cgroup" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- testmod cross-module kfuncs (test_ksyms_module.c) ----
        //   void bpf_testmod_test_mod_kfunc(int)
        //   void bpf_testmod_invalid_mod_kfunc(void)  (weak — present
        //   only when the test module is loaded; programs guard with
        //   ksym null check)
        "bpf_testmod_test_mod_kfunc" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }
        "bpf_testmod_invalid_mod_kfunc" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
        }

        // ---- bpf_copy_from_user_str ----
        // int bpf_copy_from_user_str(void *dst, u32 size,
        //                            const void *unsafe_ptr, u64 flags)
        // Used by test_attach_probe.c sleepable uprobes. Modeled with
        // a writable pointer + size pair so the bounds check matches
        // the kernel's KF_ARG_PTR_TO_UNINIT_MEM rules.
        "bpf_copy_from_user_str" => CallProto::with_args([
            PtrToUninitMem,
            ConstSizeOrZero,
            Anything,
            Anything,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .mem_size_pairs(&pairs::COPY_FROM_USER_STR)
        // KF_SLEEPABLE: rejects calls inside preempt-disabled or
        // IRQ-disabled regions. Kernel `fn->might_sleep`. Without
        // this flag, irq.c::irq_sleepable_kfunc and
        // preempt_lock.c::preempt_sleepable_kfunc would PASS→FA.
        .flags(CallFlags::MIGHT_SLEEP),

        // int bpf_copy_from_user_task(void *dst, u32 size,
        //                              const void __user *src,
        //                              struct task_struct *task,
        //                              u64 flags)
        // Same as bpf_copy_from_user but reads from another task's
        // address space. KF_SLEEPABLE.
        "bpf_copy_from_user_task" => CallProto::with_args([
            PtrToUninitMem,
            ConstSize,
            Anything,
            PtrToBtfIdNamed {
                type_name: "task_struct",
            },
            Anything,
        ])
        .ret(RetKind::Scalar)
        .mem_size_pairs(&pairs::COPY_FROM_USER_STR)
        .flags(CallFlags::MIGHT_SLEEP),

        // int bpf_copy_from_user_task_str(void *dst, u32 size,
        //                                  const void __user *src,
        //                                  struct task_struct *task,
        //                                  u64 flags)
        // String variant — null-terminates and bounds the read.
        "bpf_copy_from_user_task_str" => CallProto::with_args([
            PtrToUninitMem,
            ConstSize,
            Anything,
            PtrToBtfIdNamed {
                type_name: "task_struct",
            },
            Anything,
        ])
        .ret(RetKind::Scalar)
        .mem_size_pairs(&pairs::COPY_FROM_USER_STR)
        .flags(CallFlags::MIGHT_SLEEP),

        // ---- bpf_sock_destroy (sock_destroy_prog.c) ----
        // int bpf_sock_destroy(struct sock_common *sk)
        // KF_TRUSTED_ARGS — invokes the kernel's sock-destroy path on
        // a trusted sock_common pointer (typically obtained from a
        // bpf_iter/tcp or bpf_iter/udp ctx). Returns negative errno or 0.
        // Kernel registers it for BPF_PROG_TYPE_TRACING/BPF_TRACE_ITER
        // only — programs in sock_destroy_prog.c use SEC("iter/{tcp,udp}")
        // which we type as Tracing kind. Anything-arg accepts both
        // PtrToBtfId{sock_common} (from iter ctx) and (struct sock_common
        // *) casts of typed sock pointers.
        "bpf_sock_destroy" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- bpf_get_kmem_cache (kmem_cache_iter.c) ----
        // struct kmem_cache *bpf_get_kmem_cache(u64 addr)
        // Returns a kernel slab cache pointer. Programs only use it
        // for null-check + map-lookup-by-pointer-value (no field
        // access on the returned pointer in test corpus), so a
        // Scalar return is sufficient.
        "bpf_get_kmem_cache" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- bpf_sock_addr_set_sun_path ----
        // int bpf_sock_addr_set_sun_path(struct bpf_sock_addr_kern *,
        //                                const __u8 *sun_path,
        //                                __u32 sun_path__sz)
        // Used by connect_unix_prog.c, getsockname_unix_prog.c,
        // getpeername_unix_prog.c, sendmsg_unix_prog.c,
        // recvmsg_unix_prog.c. Programs only use the int return for
        // an early-return; sa_kern field access still depends on
        // bpf_core_cast typing (separate gap).
        "bpf_sock_addr_set_sun_path" => {
            CallProto::with_args([Anything, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- bpf_get_fsverity_digest ----
        // int bpf_get_fsverity_digest(struct file *,
        //                             struct bpf_dynptr *digest_ptr)
        // Used by test_fsverity.c, test_sig_in_xattr.c. file arg is
        // Anything to accept the BPF_PROG-entry PtrToBtfId{file}.
        "bpf_get_fsverity_digest" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- bpf_verify_pkcs7_signature ----
        // int bpf_verify_pkcs7_signature(struct bpf_dynptr *data,
        //                                struct bpf_dynptr *sig,
        //                                struct bpf_key *trusted_keyring)
        // Used by test_verify_pkcs7_sig.c, test_kfunc_dynptr_param.c,
        // test_sig_in_xattr.c. KF_SLEEPABLE per kernel registration.
        // First two args are dynptrs (consumer shape — slot must be
        // initialized); third is a refcounted bpf_key from
        // bpf_lookup_user_key / bpf_lookup_system_key.
        "bpf_verify_pkcs7_signature" => CallProto::with_args([
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            },
            DynptrArg {
                uninit: false,
                rdwr_only: false,
            },
            Anything,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .flags(CallFlags::MIGHT_SLEEP),

        // ---- bpf_rdonly_cast / bpf_core_cast ----
        // void *bpf_rdonly_cast(const void *obj, __u32 btf_id)
        // The kernel returns a pointer with the BTF type identified
        // by R2, with PTR_TRUSTED|MEM_RDONLY flags. R0 typing is
        // post-call: kfunc.rs reads R2's fixed value, looks up the
        // struct name in BTF, and stamps R0 as PtrToBtfId{name,
        // TRUSTED}. Used by sock_iter_batch.c, type_cast.c, and
        // the *_unix_prog family (via bpf_core_cast macro).
        // Registered as RetKind::Unknown so apply_call_proto_r0
        // doesn't clobber R0; the post-call hook sets it.
        "bpf_rdonly_cast" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
        }

        // ---- Sched_ext kfuncs ----
        //
        // All gated to `ProgramKind::StructOps` — the kernel registers
        // these against the sched_ext class. Task-pointer args use
        // `PtrToBtfId` (we don't model `task_struct` field offsets);
        // dsq_id / cpu / flags args are scalars (`Anything`). The
        // *_bstr variadic-error/exit kfuncs accept any pointer for the
        // fmt/data args — the kernel does its own probe-read; over-
        // approximating to `Anything` matches our existing trace_printk
        // shape.

        // void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id,
        //                         u64 slice, u64 enq_flags)
        "scx_bpf_dsq_insert" => {
            CallProto::with_args([PtrToBtfId, Anything, Anything, Anything, DontCare])
                .ret(RetKind::Void)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // void scx_bpf_dsq_insert_vtime(struct task_struct *p, u64 dsq_id,
        //                               u64 slice, u64 vtime, u64 enq_flags)
        "scx_bpf_dsq_insert_vtime" => {
            CallProto::with_args([PtrToBtfId, Anything, Anything, Anything, Anything])
                .ret(RetKind::Void)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // s32 scx_bpf_create_dsq(u64 dsq_id, s32 node)
        "scx_bpf_create_dsq" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // void scx_bpf_destroy_dsq(u64 dsq_id)
        "scx_bpf_destroy_dsq" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // bool scx_bpf_dsq_move_to_local(u64 dsq_id)
        "scx_bpf_dsq_move_to_local" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // s32 scx_bpf_task_cpu(const struct task_struct *p)
        "scx_bpf_task_cpu" => {
            CallProto::with_args([PtrToBtfId, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu,
        //                            u64 wake_flags, bool *is_idle)
        // R4 is an output pointer; we accept any pointer (`Anything`)
        // here since the corpus passes a stack address and the kernel
        // verifier checks PTR_TO_STACK separately.
        // kernel gates this kfunc to `sched_ext_ops.select_cpu`
        // context only — calling it from `.enqueue` (or any other
        // member) rejects with the kfunc-context check. See
        // `selftests/sched_ext/enq_select_cpu_fails.bpf.c`.
        "scx_bpf_select_cpu_dfl" => {
            CallProto::with_args([PtrToBtfId, Anything, Anything, Anything, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
                .ops_member_allowlist(&[("sched_ext_ops", "select_cpu")])
        }

        // void scx_bpf_error_bstr(char *fmt, unsigned long long *data,
        //                         u32 data_len)
        // Variadic error-reporting kfunc; backs the scx_bpf_error()
        // wrapper macro. fmt/data are pointers we don't tightly type.
        "scx_bpf_error_bstr" => {
            CallProto::with_args([Anything, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::Void)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // void scx_bpf_exit_bstr(s64 exit_code, char *fmt,
        //                        unsigned long long *data, u32 data__sz)
        "scx_bpf_exit_bstr" => {
            CallProto::with_args([Anything, Anything, Anything, Anything, DontCare])
                .ret(RetKind::Void)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // bool scx_bpf_test_and_clear_cpu_idle(s32 cpu)
        "scx_bpf_test_and_clear_cpu_idle" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // s32 scx_bpf_pick_idle_cpu(const cpumask_t *cpus_allowed, u64 flags)
        // s32 scx_bpf_pick_any_cpu(const cpumask_t *cpus_allowed, u64 flags)
        // Cpumask args reuse `PtrToCpumask` (the const cpumask vs
        // bpf_cpumask distinction isn't modeled — see bpf_cpumask_first).
        "scx_bpf_pick_idle_cpu" => {
            CallProto::with_args([PtrToCpumask, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        "scx_bpf_pick_any_cpu" => {
            CallProto::with_args([PtrToCpumask, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // const struct cpumask *scx_bpf_get_idle_cpumask(void)
        // const struct cpumask *scx_bpf_get_idle_smtmask(void)
        // KF_ACQUIRE — paired with scx_bpf_put_idle_cpumask.
        "scx_bpf_get_idle_cpumask" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToCpumask)
                .flags(CallFlags::ACQUIRE)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        "scx_bpf_get_idle_smtmask" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToCpumask)
                .flags(CallFlags::ACQUIRE)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // void scx_bpf_put_idle_cpumask(const struct cpumask *cpumask)
        // void scx_bpf_put_cpumask(const struct cpumask *cpumask)
        // KF_RELEASE — drops the implicit ref from a get_*_cpumask call.
        "scx_bpf_put_idle_cpumask" => {
            CallProto::with_args([PtrToCpumask, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .flags(CallFlags::RELEASE)
                .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }])
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        "scx_bpf_put_cpumask" => {
            CallProto::with_args([PtrToCpumask, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Void)
                .flags(CallFlags::RELEASE)
                .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }])
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // ---- NUMA-aware variants used by numa.bpf.c ----

        // u32 scx_bpf_nr_node_ids(void)
        "scx_bpf_nr_node_ids" => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // int scx_bpf_cpu_node(s32 cpu)
        "scx_bpf_cpu_node" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // const struct cpumask *scx_bpf_get_idle_cpumask_node(int node)
        "scx_bpf_get_idle_cpumask_node" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::PtrToCpumask)
                .flags(CallFlags::ACQUIRE)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // s32 scx_bpf_pick_idle_cpu_node(const cpumask_t *cpus_allowed,
        //                                int node, u64 flags)
        "scx_bpf_pick_idle_cpu_node" => {
            CallProto::with_args([PtrToCpumask, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // s32 scx_bpf_pick_any_cpu_node(const cpumask_t *cpus_allowed,
        //                               int node, u64 flags)
        "scx_bpf_pick_any_cpu_node" => {
            CallProto::with_args([PtrToCpumask, Anything, Anything, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // ---- compat.bpf.h CO-RE aliases for older kernels ----
        //
        // The scx_bpf_dsq_insert(), scx_bpf_dsq_move_to_local() etc.
        // macros expand to a `bpf_ksym_exists(modern) ? modern(...) :
        // legacy___compat(...)` ternary. Both kfunc names are emitted
        // as relocs at compile time; libbpf picks one at load time.
        // For our purposes we accept both with the same proto.
        "scx_bpf_dispatch___compat" => {
            CallProto::with_args([PtrToBtfId, Anything, Anything, Anything, DontCare])
                .ret(RetKind::Void)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        "scx_bpf_dispatch_vtime___compat" => {
            CallProto::with_args([PtrToBtfId, Anything, Anything, Anything, Anything])
                .ret(RetKind::Void)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        "scx_bpf_consume___compat" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&SCHED_EXT_KFUNC_PROG_TYPES)
        }

        // ---- bpf_testmod struct_ops kfuncs ----
        // int bpf_kfunc_st_ops_inc10(struct st_ops_args *args)
        // Trivial test kfunc invoked from struct_ops prologue/epilogue
        // tests (`pro_epilogue.c`, `pro_epilogue_with_kfunc.c`). The
        // single arg is a kernel-typed pointer (PtrToBtfId / NULL); we
        // accept Anything since the test bodies don't read through the
        // returned scalar.
        "bpf_kfunc_st_ops_inc10" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // void *bpf_cast_to_kern_ctx(void *obj)
        // Reinterpret a uapi BPF ctx pointer as the corresponding kernel
        // type (e.g. __sk_buff -> sk_buff). Test bodies just call it and
        // either ignore the return or store/load through the same alias;
        // returning Scalar (no precise pointer typing yet) is sufficient
        // to clear the dispatch-time rejection.
        // R0 typed in kfunc.rs by per-ProgramKind kernel-ctx mapping
        // (kernel verifier `find_kern_ctx_type_id` /
        // `BPF_PROG_TYPE_*` table). Without that, programs that cast
        // via `bpf_cast_to_kern_ctx` then deref the kern struct's
        // fields (sa_kern->uaddrlen on bpf_sock_addr_kern, etc.) FR
        // on the deref. RetKind::Unknown defers R0 typing to the
        // post-call hook.
        "bpf_cast_to_kern_ctx" => {
            CallProto::with_args([Anything, DontCare, DontCare, DontCare, DontCare])
        }

        // int bpf_sock_ops_enable_tx_tstamp(struct bpf_sock_ops_kern *skops, u64 flags)
        // Enables egress TX timestamping on the socket associated with
        // `skops`. Registered to BPF_PROG_TYPE_SOCK_OPS only (kernel
        // `bpf_sock_ops_kfunc_set` in net/core/filter.c). Used by
        // `net_timestamping::skops_sockopt` after a
        // `bpf_cast_to_kern_ctx` from the bpf_sock_ops ctx. R1 is
        // accepted as Anything — the cast-to-kern-ctx return is typed
        // as `PtrToBtfId{"bpf_sock_ops_kern", TRUSTED}` and the test
        // body doesn't deref it through us; we just need to clear the
        // dispatch-time "unknown kfunc" rejection.
        "bpf_sock_ops_enable_tx_tstamp" => {
            CallProto::with_args([Anything, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
                .prog_type_allowlist(&SOCK_OPS_KFUNC_PROG_TYPES)
        }

        _ => return None,
    })
}

// Static mem-size-pair arrays referenced inline by helper / kfunc protos
// (: was helper-id-keyed via the now-deleted `get_mem_size_pairs`;
// pairs now ride on `CallProto::mem_size_pairs` so the same machinery
// serves both helpers and kfuncs).
//
// BPF_RINGBUF_OUTPUT is intentionally absent — the kernel allows
// reading uninitialized stack data in privileged mode; restoring this
// pair needs privileged/unprivileged-mode support.
