// src/analysis/transfer/call/signatures.rs
//
// Call-proto type definitions: ArgKind, CallFlags, RetKind, SideEffect,
// CallProto, MemSizePair. Proto tables live in helper_protos.rs / kfunc_protos.rs.

// Re-export proto tables so callers can still use `super::signatures::get_*`.
pub(crate) use super::helper_protos::{
    get_helper_proto, get_nullable_ptr_size_pair, helper_rejects_packet_for_arg,
};
pub(crate) use super::kfunc_protos::get_kfunc_proto;

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::stack_state::{DynptrKind, IrqKfuncClass, IterKind};
use crate::parsing::btf::SpecialFieldKind;

// ============================================================================
// ArgKind — per-argument expected shape
// ============================================================================

/// Expected shape of a call argument (R1..R5).
///
/// Expected shape of a call argument (R1..R5). Covers helpers and kfuncs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ArgKind {
    /// Unused argument slot
    DontCare,

    // ---- Map-related ----
    ConstMapPtr,
    /// `ConstMapPtr` whose backing `BpfMapDef::type_` must equal the given
    /// kernel `BPF_MAP_TYPE_*` value. Used by kfuncs (e.g. arena alloc/free)
    /// that demand a specific map kind. Distinct from `ConstMapPtr`'s
    /// helper-id-driven type table because kfunc dispatch doesn't go
    /// through `helper_id_by_name`.
    ConstMapPtrOfType(u32),
    PtrToMapKey,
    PtrToMapValue,
    PtrToUninitMapValue,

    // ---- Memory access ----
    PtrToMem,
    PtrToUninitMem,
    PtrToAllocMem,
    /// Pointer to a const, NUL-terminated string in a read-only map
    /// value (`.rodata`). Mirrors kernel `ARG_PTR_TO_CONST_STR`
    /// (`verifier.c::check_reg_const_str`, v6.15 ~L9405): rejects
    /// `PtrToMapValue` whose map is NOT `BPF_F_RDONLY_PROG`. Used by
    /// `bpf_snprintf`'s fmt arg.
    PtrToConstStr,

    // ---- Size ----
    ConstSize,
    ConstSizeOrZero,
    ConstAllocSizeOrZero,

    // ---- Context / general ----
    PtrToCtx,
    Anything,

    // ---- Socket ----
    PtrToSockCommon,
    PtrToSocket,
    PtrToBTFIdSockCommon,

    // ---- BTF ID ----
    PtrToBtfId,
    /// `PtrToBtfId` whose `type_name` must equal the given kernel
    /// struct name. Stricter than `PtrToBtfId` (which accepts any
    /// named BTF pointer): used by kfuncs that demand a specific
    /// struct (`bpf_path_d_path` requires `struct path *` — kernel
    /// rejects `struct file *` interior pointers like
    /// `&file->f_task_work` cast to `(struct path *)`). The new
    /// per-field BTF arithmetic in `update_ptr_arithmetic_type`
    /// produces correctly-typed interior pointers so this name
    /// match becomes meaningful.
    PtrToBtfIdNamed { type_name: &'static str },

    // ---- Stack ----
    PtrToStack,

    // ---- Nullable variants ----
    PtrToCtxOrNull,
    PtrToMemOrNull,
    /// Writable buffer or NULL. Mirrors kernel
    /// `ARG_PTR_TO_MEM | PTR_MAYBE_NULL` for write helpers like
    /// `bpf_snprintf` (buf may be NULL when paired size = 0,
    /// switching the helper into "compute formatted length only" mode).
    PtrToUninitMemOrNull,
    PtrToStackOrNull,
    PtrToMapValueOrNull,

    // ---- Fixed-size pointer ----
    PtrToLong,

    // ---- Callback ----
    /// Subprog pointer (`RegType::PtrToCallback`). Used by callback-
    /// taking kfuncs like `bpf_set_exception_callback`.
    PtrToCallback,

    // ---- Dynptr ----
    /// `&bpf_dynptr` on the stack (a `PtrToStack` aimed at a 16-byte
    /// dynptr pair).
    ///
    /// `uninit = true` means the kfunc is the *constructor* — the slot
    /// must be uninitialized (no prior dynptr annotation). `false` means
    /// the kfunc is a *consumer* — the slot must hold an initialized
    /// dynptr at its first slot.
    ///
    /// `rdwr_only = true` rejects rdonly dynptrs (e.g. `bpf_dynptr_write`,
    /// `bpf_dynptr_slice_rdwr`). `false` accepts both rdonly and rdwr.
    DynptrArg { uninit: bool, rdwr_only: bool },

    // ---- Iterator ----
    /// `&bpf_iter_*` on the stack. The iterator's kind and lifecycle
    /// state are tracked via `IteratorSlot`; this arg shape encodes both
    /// the expected `kind` and what slot states the kfunc accepts.
    ///
    /// - `Uninit`            — no prior annotation (constructor sink).
    /// - `Active`            — slot must be live (consumer: `*_next`).
    /// - `ActiveOrDrained`   — accept either (destructor sink).
    IterArg { kind: IterKind, expected: IterArgExpect },

    // ---- IRQ flag ----
    /// `unsigned long *` on the stack pointing at an 8-byte slot used
    /// to hold an IRQ flag. `uninit = true` is the constructor (the
    /// slot must have NO IRQ_FLAG annotation, NO iter/dynptr annotation,
    /// and not carry an outstanding ref). `uninit = false` is the
    /// destructor (slot must carry an IRQ_FLAG annotation whose
    /// `kfunc_class` matches and whose `id` equals `active_irq_id`).
    IrqFlagArg { uninit: bool, kfunc_class: IrqKfuncClass },

    /// `bpf_res_spin_lock{,_irqsave}` / `_unlock{,_irqrestore}` arg.
    /// Mirrors kernel `KF_ARG_PTR_TO_RES_SPIN_LOCK` (verifier.c v6.15
    /// L13347): R must be `PtrToMapValue` or `PtrToOwnedKptr`; the
    /// reg's `var_off + reg.off` must equal the BTF-recorded
    /// `res_spin_lock` field offset of the pointee record (L8310);
    /// the map/struct must carry a `bpf_res_spin_lock` field (L8305).
    /// `is_irq` distinguishes the irqsave variant — used at the
    /// acquire/release transfer to flag the entry's `is_irq` field
    /// for the LIFO-match check.
    ResSpinLockArg { is_irq: bool },

    // ---- Cpumask ----
    /// `struct bpf_cpumask *` argument — mutating consumers only
    /// (`bpf_cpumask_set_cpu`, `_clear_cpu`, `_clear`, `_copy`,
    /// `_release`, …). Strict: only the acquire-tracked
    /// `RegType::PtrToCpumask` is accepted, so the program must have
    /// passed an actual `bpf_cpumask` allocated via
    /// `bpf_cpumask_create` / acquired via `bpf_cpumask_acquire`.
    /// `(struct bpf_cpumask *)task->cpus_ptr` casts (read-only kernel
    /// `cpumask`) are rejected here — kernel error
    /// "Can't set the CPU of a non-struct bpf_cpumask".
    PtrToCpumask,
    /// `const struct cpumask *` argument — read-only consumers
    /// (`bpf_cpumask_test_cpu`, `_first`, `_first_zero`, `_full`,
    /// `_empty`, `_equal`, `_intersects`, `_subset`, `_weight`, …).
    /// Accepts `PtrToCpumask` (the bpf_cpumask wrapper is also a
    /// const cpumask) AND `PtrToBtfId{type_name in {"cpumask",
    /// "bpf_cpumask"}, TRUSTED}` produced by the BTF field-load
    /// typing path (`task->cpus_ptr`, `&task->cpus_mask`).
    PtrToCpumaskRead,

    // ---- Cgroup ----
    /// `struct cgroup *` argument. Same shape as `PtrToCpumask` —
    /// only the non-null `RegType::PtrToCgroup` is accepted; the
    /// program must have null-checked a freshly minted ref before
    /// passing it to `bpf_cgroup_acquire` / `bpf_cgroup_release`.
    PtrToCgroup,

    // ---- Task ----
    /// `struct task_struct *` argument. Same shape as `PtrToCgroup` —
    /// only the non-null `RegType::PtrToTask` accepted. Program must
    /// have null-checked a `bpf_task_acquire` / `bpf_task_from_pid`
    /// result first; `bpf_get_current_task_btf` returns a non-null
    /// task directly.
    PtrToTask,

    // ---- Arena ----
    /// Bounded arena memory pointer. The actual reg must be a non-null,
    /// ref-tracked `RegType::PtrToArena` (i.e. the program has already
    /// null-checked a freshly allocated arena range). Drives
    /// `bpf_arena_free_pages`'s pointer-arg validation; also reused by
    /// future arena-consumer kfuncs.
    PtrToArena,

    // ---- Owned kptr ----
    /// Refcounted heap-allocated kernel object. The actual reg must be
    /// a non-null, ref-tracked `RegType::PtrToOwnedKptr` (the program
    /// has already null-checked an alloc / pop / refcount_acquire
    /// result). Drives `bpf_obj_drop_impl`, `bpf_refcount_acquire_impl`,
    /// and the list/rbtree push kfuncs (which release the ref).
    PtrToOwnedKptr,

    // ---- Map-value special field ----
    /// Pointer into a map value, aimed at a specific kernel-defined
    /// field embedded in the value (e.g. `bpf_timer`, `bpf_spin_lock`).
    /// The actual reg must be `PtrToMapValue { offset, map_idx }` where
    /// the map's value BTF carries a `SpecialField` of `kind` at exactly
    /// `offset`. Drives `bpf_timer_*` arg validation; future use will
    /// cover real `bpf_spin_lock` pointer args and rbtree/list
    MapValueSpecial { kind: SpecialFieldKind },
}

/// Required slot state for an `IterArg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum IterArgExpect {
    Uninit,
    Active,
    ActiveOrDrained,
}

// ============================================================================
// CallFlags / RetKind / SideEffect — post-call semantics
// ============================================================================

/// Behavioral flags attached to a call proto.
///
/// For helpers these are currently all unset — existing post-call
/// logic in `transfer.rs` / `types.rs` handles acquire/release/
/// ret-null by helper-id switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CallFlags(u32);

#[allow(dead_code)]
impl CallFlags {
    /// Return value is a freshly-acquired reference (track it).
    pub const ACQUIRE: Self = Self(1 << 0);
    /// One arg (by convention the first ref-typed ptr) is released.
    pub const RELEASE: Self = Self(1 << 1);
    /// Return value may be NULL — fork null / non-null successors.
    pub const RET_NULL: Self = Self(1 << 2);
    /// All pointer args must be trusted (kfunc KF_TRUSTED_ARGS).
    pub const TRUSTED_ARGS: Self = Self(1 << 3);
    /// Must run inside an RCU read-side critical section. Pre-call check
    /// rejects if `state.rcu_read_depth == 0`.
    pub const RCU: Self = Self(1 << 4);
    /// Callable only from sleepable programs.
    pub const SLEEPABLE: Self = Self(1 << 5);
    /// Destructive kfunc (KF_DESTRUCTIVE).
    pub const DESTRUCTIVE: Self = Self(1 << 6);
    /// Pre-call: acquires the spin_lock pointed to by R1 (which the
    /// `MapValueSpecial { SpinLock }` arg validator has already shape-
    /// checked). Rejects if a lock is already held; otherwise records
    /// `(ptr_id, lock_offset)` in `state.active_lock`.
    pub const SPIN_LOCK_ACQUIRE: Self = Self(1 << 7);
    /// Pre-call: releases the spin_lock pointed to by R1. Rejects if no
    /// lock is held or if the held lock's `ptr_id` doesn't match R1's.
    /// .
    pub const SPIN_LOCK_RELEASE: Self = Self(1 << 8);
    /// Pre-call: enters an RCU read-side critical section by
    /// incrementing `state.rcu_read_depth`.
    pub const RCU_READ_LOCK: Self = Self(1 << 9);
    /// Pre-call: exits an RCU read-side critical section by
    /// decrementing `state.rcu_read_depth`. Rejects if depth is already
    pub const RCU_READ_UNLOCK: Self = Self(1 << 10);
    /// Pre-call precondition: a spin_lock must be held. Drives
    /// rbtree / list mutation kfuncs which would race on the per-map-
    /// value head/root without the lock. Rejects with
    /// `NotInSpinLockSection` when `state.active_lock.is_none()`.
    pub const SPIN_LOCK_HELD: Self = Self(1 << 11);
    /// Post-call: skip the default caller-saved clobber of R1..R5
    /// (regtypes + DBM + tnum + scalar_id). The kernel's `bpf_fastcall`
    /// calling-convention hint (v6.13) lets clang emit shorter
    /// sequences around these calls because R1..R5 retain their
    /// pre-call values. Used by select helpers (see `is_fastcall_helper`)
    /// and per-kfunc on cpumask read-only queries.
    pub const FASTCALL: Self = Self(1 << 12);
    /// Pre-call: enters a preempt-disabled region by incrementing
    /// `state.active_preempt_locks`. Mirrors kernel `bpf_preempt_disable`
    /// kfunc (verifier.c v6.15 ~L13569).
    pub const PREEMPT_DISABLE: Self = Self(1 << 13);
    /// Pre-call: exits a preempt-disabled region. Rejects if the count
    /// is already zero (unmatched enable). Mirrors kernel
    /// `bpf_preempt_enable` kfunc (verifier.c v6.15 ~L13571).
    pub const PREEMPT_ENABLE: Self = Self(1 << 14);
    /// Pre-call: this helper/kfunc may sleep. Rejected when
    /// `state.in_preempt_disabled()`. Mirrors kernel `fn->might_sleep`
    /// (verifier.c v6.15 ~L11299) and `KF_SLEEPABLE` for kfuncs (~L13565).
    pub const MIGHT_SLEEP: Self = Self(1 << 15);
    /// Post-call: this `RELEASE`-flagged kfunc converts the released
    /// argument's owning ref into a non-owning ref instead of fully
    /// invalidating it. Mirrors kernel `verifier.c` v6.15
    /// `ref_convert_owning_non_owning` (L12471), driven by the
    /// `KF_RELEASE` flag on graph-add kfuncs (`bpf_rbtree_add_impl`,
    /// `bpf_list_push_{front,back}_impl`). Without this, the original
    /// alloc-pointer becomes Scalar after add and a follow-up
    /// `bpf_refcount_acquire(n)` (under the same lock) fails its arg
    /// type check.
    pub const RELEASE_NON_OWN: Self = Self(1 << 16);
    /// Pre-call: this kfunc disables IRQs and stamps `arg #0`'s stack
    /// slot as an IRQ flag. Pushes a fresh id on `acquired_irq_ids`.
    /// Drives the `IrqSaveOnArg` side effect.
    pub const IRQ_SAVE: Self = Self(1 << 17);
    /// Pre-call: this kfunc restores IRQ state from `arg #0`'s slot.
    /// Rejects unless the slot's id matches `active_irq_id` (LIFO).
    /// Drives the `IrqRestoreFromArg` side effect.
    pub const IRQ_RESTORE: Self = Self(1 << 18);
    /// Pre-call: `bpf_res_spin_lock` family acquire. The transfer
    /// function forks the state at the call insn (kernel `push_stack`,
    /// verifier.c v6.15 L13455-13479): success branch with R0=0 and
    /// the lock pushed on `acquired_res_locks`; failure branch with R0
    /// constrained to negative (no lock pushed). AA-deadlock check fires
    /// before push.
    pub const RES_SPIN_LOCK_ACQUIRE: Self = Self(1 << 19);
    /// Pre-call: `bpf_res_spin_unlock` family. Validates LIFO match on
    /// `acquired_res_locks` (kernel L8369-8376) — emits "different
    /// lock" / "out of order" errors as appropriate.
    pub const RES_SPIN_LOCK_RELEASE: Self = Self(1 << 20);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl core::ops::BitOr for CallFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl core::ops::BitOrAssign for CallFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Shape of R0 after the call.
///
/// `Unknown` = legacy `update_call_types` arm decides R0's type by
/// helper-id. Concrete variants drive R0 typing through the shared
/// post-call applier (`call::side_effects`) so kfuncs can reuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub enum RetKind {
    /// Legacy fallback — leave R0 alone; per-helper logic sets it.
    #[default]
    Unknown,
    /// Kfunc returns `void`. Post-call applier leaves R0 = Scalar (BPF
    /// ABI gives every callee an R0; we don't expose any constraints).
    Void,
    /// Generic scalar return.
    Scalar,
    /// `RegType::PtrToSocket`. Combined with `CallFlags::ACQUIRE` the
    /// applier mints a fresh ref_id; combined with `CallFlags::RET_NULL`
    /// the result wraps as `PtrToSocketOrNull`.
    PtrToSocket,
    /// `RegType::PtrToSockCommon`. Same acquire/null semantics as above.
    PtrToSockCommon,
    /// `RegType::PtrToAllocMem` sized by the value of the arg at index
    /// `size_arg`. Used by `bpf_dynptr_slice`/`slice_rdwr`,
    /// which return a pointer into the dynptr's backing memory whose
    /// length matches the caller-supplied scratch-buffer size. Combined
    /// with `CallFlags::RET_NULL` the applier wraps as
    /// `PtrToAllocMemOrNull`.
    PtrToAllocMemFromArg { size_arg: u8 },
    /// Same as `PtrToAllocMemFromArg` but stamps `rdonly: true` on the
    /// returned `PtrToAllocMem*`. Used by `bpf_dynptr_slice` (kernel
    /// returns `const void *`) so subsequent stores through the slice
    /// reject with "cannot write into rdonly_mem". `bpf_dynptr_slice_rdwr`
    /// keeps the non-rdonly variant.
    PtrToAllocMemFromArgRdonly { size_arg: u8 },
    /// `RegType::PtrToAllocMem` with a const element size baked in
    /// . Used by `bpf_iter_*_next` whose returned pointer width
    /// is per-iter-kind, not driven by an arg. Combined with
    /// `CallFlags::RET_NULL` the applier wraps as `PtrToAllocMemOrNull`.
    PtrToAllocMem { mem_size: u64 },
    /// `RegType::PtrToCpumask`. `bpf_cpumask_create` returns a
    /// freshly-acquired cpumask. Combined with `CallFlags::ACQUIRE` the
    /// applier mints a fresh ref_id; combined with `CallFlags::RET_NULL`
    /// the result wraps as `PtrToCpumaskOrNull`.
    PtrToCpumask,
    /// `RegType::PtrToArena`. Used by `bpf_arena_alloc_pages`
    /// whose returned bounded-memory size is `R(page_cnt_arg+1) * PAGE_SIZE`
    /// — i.e. the page count argument scaled by the architectural page
    /// size (4096). Combined with `CallFlags::ACQUIRE` the applier mints
    /// a fresh ref_id; combined with `CallFlags::RET_NULL` the result
    /// wraps as `PtrToArenaOrNull`.
    PtrToArenaFromArg { page_cnt_arg: u8 },
    /// `RegType::PtrToOwnedKptr`. Used by `bpf_obj_new_impl`,
    /// `bpf_refcount_acquire_impl`, and the list/rbtree pop/remove
    /// kfuncs. Combined with `CallFlags::ACQUIRE` the applier mints a
    /// fresh ref_id; combined with `CallFlags::RET_NULL` the result
    /// wraps as `PtrToOwnedKptrOrNull`.
    PtrToOwnedKptr,
    /// `RegType::PtrToCgroup`. Used by `bpf_cgroup_from_id`
    /// and `bpf_cgroup_acquire`. Same applier shape as `PtrToCpumask`:
    /// `ACQUIRE` mints a ref, `RET_NULL` wraps as `PtrToCgroupOrNull`.
    PtrToCgroup,
    /// `RegType::PtrToTask`. Used by
    /// `bpf_get_current_task_btf` (no acquire), `bpf_task_acquire`,
    /// `bpf_task_from_pid`. Same applier shape as `PtrToCgroup`:
    /// `ACQUIRE` mints a ref, `RET_NULL` wraps as `PtrToTaskOrNull`.
    PtrToTask,
    /// `RegType::PtrToBtfId { type_name, flags: TRUSTED }` for kernel
    /// types that don't have a dedicated reg-type specialization
    /// (e.g. `struct file *` from `bpf_get_task_exe_file`,
    /// `struct bpf_key *` from `bpf_lookup_user_key`,
    /// `struct sk_buff *` from `bpf_kfunc_nested_acquire_*_test`).
    /// `ACQUIRE` mints a `ref_id` carried on the variant so the
    /// matching `KF_RELEASE` consumer (`bpf_put_file`, `bpf_key_put`,
    /// `bpf_kfunc_nested_release_test`) finds it via `get_ref_id()`;
    /// `RET_NULL` wraps as `PtrToBtfIdOrNull` so the program must
    /// null-check before passing the pointer to a `PtrToBtfId`-arg
    /// kfunc (the kernel's "Possibly NULL pointer passed to trusted
    /// arg0" diagnostic).
    PtrToBtfIdNamed { type_name: &'static str },
    /// `bpf_iter_*_next(&it)`: forks the call into two
    /// successors. Non-NULL: R0 = `PtrToAllocMem { mem_size = elem_size }`,
    /// iterator slot at `iter_arg` stays Active. NULL: R0 = scalar 0,
    /// slot transitions Active → Drained. The kfunc dispatcher in
    /// `transfer_kfunc_proto` recognizes this variant and produces both
    /// successors; the flat-state applier `apply_call_proto_r0` does
    /// not handle it (would assert).
    IterNextElem { iter_arg: u8, elem_size: u64 },
    /// Typed `_next` return: same fork shape as `IterNextElem` but R0
    /// on the non-NULL successor is `PtrToBtfId { type_name, flags,
    /// ref_id: None }` instead of generic `PtrToAllocMem`. Used by
    /// `bpf_iter_task_vma_next` (TRUSTED `vm_area_struct *`) and
    /// `bpf_iter_task_next` (RCU `task_struct *`). The matching
    /// consumer kfunc's flag enforcement (`KF_TRUSTED_ARGS` /
    /// `KF_RCU`) inspects `PtrFlags` to accept or reject — that's
    /// what keeps `iter_next_rcu_not_trusted`'s call to
    /// `bpf_kfunc_trusted_task_test` rejected (RCU isn't TRUSTED).
    IterNextBtfId {
        iter_arg: u8,
        type_name: &'static str,
        flags: crate::analysis::machine::reg_types::PtrFlags,
    },
}

/// Post-call side effect entries — applied in order by the shared
/// applier. Today only the release pattern; / add dynptr/iter
/// transitions, stack-buffer init, etc.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
pub enum SideEffect {
    /// Drop & invalidate the ref carried on the given arg index (0..=4
    /// → R1..R5). Drives `bpf_sk_release` and ref-release kfuncs.
    ReleaseRefFromArg { arg: u8 },
    /// Read a `PtrToCallback { subprog_pc }` from the given arg and
    /// register that subprog as the program-default exception handler.
    /// Drives `bpf_set_exception_callback`.
    SetExceptionCallbackFromArg { arg: u8 },
    /// Stamp a fresh dynptr annotation on the stack pair pointed to by
    /// `arg`. For acquire-tracked kinds (`Ringbuf`) the applier
    /// mints a ref_id and links it onto the slot; for non-acquire kinds
    /// the ref_id is 0. Drives `bpf_dynptr_from_mem`,
    /// `bpf_ringbuf_reserve_dynptr`, etc.
    DynptrInitOnArg {
        arg: u8,
        kind: DynptrKind,
        rdonly: bool,
    },
    /// Clear the dynptr annotation on the stack pair pointed to by `arg`
    /// and drop its ref_id. Drives `bpf_ringbuf_submit_dynptr` and
    /// `bpf_ringbuf_discard_dynptr`.
    DynptrReleaseFromArg { arg: u8 },
    /// Initialize the dynptr at `dst_arg` as a clone of the dynptr at
    /// `src_arg`: copies the source slot's `kind` / `rdonly` and shares
    /// its `ref_id` so a subsequent `bpf_ringbuf_submit_dynptr(parent)`
    /// invalidates both slots (kernel `bpf_dynptr_clone` propagates
    /// `ref_obj_id`). Mints a fresh `dynptr_id` for the clone (per-instance
    /// identity for slice tracking). Drives `bpf_dynptr_clone`.
    DynptrCloneOnArg { src_arg: u8, dst_arg: u8 },
    /// Initialize an iterator slot. Validator already accepted
    /// the arg as Uninit; the applier zeros `bpf_iter_size(kind)` bytes
    /// (matching the kernel's STACK_ITER mark) and stamps an `Active`
    /// annotation with a fresh `iter_id`. Drives `bpf_iter_*_new`.
    IterInitOnArg { arg: u8, kind: IterKind },
    /// Clear an iterator slot. Validator accepted Active|Drained
    /// at this slot; the applier wipes the annotation. Drives
    /// `bpf_iter_*_destroy`.
    IterDestroyOnArg { arg: u8 },
    /// Stamp an IRQ-flag annotation on the 8-byte stack slot pointed to
    /// by `arg`. Validator must already have rejected non-uninit slots
    /// (kernel `is_irq_flag_reg_valid_uninit` ~L1243). The applier
    /// mints a fresh id via `state.irq_save()`. Drives
    /// `bpf_local_irq_save` and `bpf_res_spin_lock_irqsave`.
    IrqSaveOnArg { arg: u8, kfunc_class: IrqKfuncClass },
    /// Clear the IRQ-flag annotation on the slot pointed to by `arg`.
    /// Validator must already have checked the slot has an IRQ_FLAG of
    /// matching kfunc_class and that its id == active_irq_id (LIFO);
    /// the applier pops the LIFO entry. Drives `bpf_local_irq_restore`
    /// and `bpf_res_spin_unlock_irqrestore`.
    IrqRestoreFromArg { arg: u8, kfunc_class: IrqKfuncClass },
}

// ============================================================================
// CallProto — unified shape for helpers and kfuncs
// ============================================================================

/// Maximum number of arguments for a BPF call (helper or kfunc).
pub const MAX_BPF_FUNC_ARGS: usize = 5;

/// Unified proto for a helper or kfunc call.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct CallProto {
    /// Argument shapes for R1..R5 (use `DontCare` for unused).
    pub args: [ArgKind; MAX_BPF_FUNC_ARGS],
    /// Return value shape; `Unknown` defers to legacy post-call logic.
    pub ret: RetKind,
    /// Behavioral flags (acquire/release/ret-null/trust/rcu/...).
    pub flags: CallFlags,
    /// Post-call state mutations to apply in order.
    pub side_effects: &'static [SideEffect],
    /// Pointer-size pairs to validate before the call: each pair links a
    /// pointer arg with the size arg that bounds its access. Drives the
    /// `check_mem_size_pairs` pass and the `validate_ptr_to_mem` skip
    /// for paired pointers (: was helper-id-keyed; now lives on
    /// the proto so kfuncs reuse the same machinery).
    pub mem_size_pairs: &'static [MemSizePair],
    /// Prog-type allowlist. `None` means "allowed in any prog
    /// type"; `Some(list)` restricts the kfunc to programs whose
    /// `ProgramKind` appears in the list. Mirrors the kernel verifier's
    /// per-kfunc `KF_PROG_TYPE_*` bitmap. Enforced once at the start of
    /// `transfer_kfunc_proto`; helper paths ignore this field.
    pub prog_type_allowlist: Option<&'static [crate::ast::ProgramKind]>,
    /// per-(ops_struct, member) allowlist for struct_ops kfuncs.
    /// `None` means "no per-member restriction". `Some(list)` restricts
    /// the kfunc to subprogs wired into one of the listed (ops_struct,
    /// member) pairs. Mirrors kernel sched_ext's per-callback kfunc
    /// gating (e.g. `scx_bpf_select_cpu_dfl` is only callable from
    /// `sched_ext_ops.select_cpu`). Enforced after `prog_type_allowlist`
    /// in `transfer_kfunc_proto`. Only consulted for `ProgramKind::StructOps`.
    pub ops_member_allowlist: Option<&'static [(&'static str, &'static str)]>,
}

impl CallProto {
    /// Minimal constructor — args only, everything else default.
    /// Used by helper table entries that haven't been flag-migrated yet.
    pub(crate) const fn with_args(args: [ArgKind; MAX_BPF_FUNC_ARGS]) -> Self {
        Self {
            args,
            ret: RetKind::Unknown,
            flags: CallFlags::empty(),
            side_effects: &[],
            mem_size_pairs: &[],
            prog_type_allowlist: None,
            ops_member_allowlist: None,
        }
    }

    /// Builder: set return shape.
    pub(crate) const fn ret(mut self, ret: RetKind) -> Self {
        self.ret = ret;
        self
    }

    /// Builder: set behavioral flags.
    pub(crate) const fn flags(mut self, flags: CallFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Builder: set post-call side effects.
    pub(crate) const fn side_effects(mut self, side_effects: &'static [SideEffect]) -> Self {
        self.side_effects = side_effects;
        self
    }

    /// Builder: set pointer-size pair list.
    pub(crate) const fn mem_size_pairs(mut self, pairs: &'static [MemSizePair]) -> Self {
        self.mem_size_pairs = pairs;
        self
    }

    /// Builder: restrict the kfunc to a specific list of `ProgramKind`s.
    /// Programs with any other prog kind will reject the call. Used by
    ///  to encode per-kfunc prog-type allowlists (cgroup / cpumask /
    /// task families gate access to syscall / tracepoint / perf_event
    /// and reject from raw_tp).
    pub(crate) const fn prog_type_allowlist(
        mut self,
        list: &'static [crate::ast::ProgramKind],
    ) -> Self {
        self.prog_type_allowlist = Some(list);
        self
    }

    /// Builder: restrict a struct_ops kfunc to a specific list of
    /// (ops_struct, member) pairs.
    pub(crate) const fn ops_member_allowlist(
        mut self,
        list: &'static [(&'static str, &'static str)],
    ) -> Self {
        self.ops_member_allowlist = Some(list);
        self
    }
}

// ============================================================================
// Pointer-Size Pair Table
// ============================================================================

/// A pointer argument paired with its size argument.
#[derive(Debug, Clone, Copy)]
pub struct MemSizePair {
    pub ptr_reg: Reg,
    pub size_reg: Reg,
    /// If true, size can be 0 (and if ptr is NULL, size MUST be 0)
    pub allow_zero: bool,
    /// If true, NULL ptr skips the size check entirely. Mirrors the
    /// kernel's `is_kfunc_arg_optional` (the `__opt` suffix) — when the
    /// pointer is NULL, no buffer access happens, so any size is fine.
    /// Used by `bpf_dynptr_slice`/`_rdwr` whose `buffer__opt` is the
    /// scratch-buffer for the slow copy path.
    pub null_skips_size_check: bool,
}

impl MemSizePair {
    pub(crate) const fn new(ptr_reg: Reg, size_reg: Reg) -> Self {
        Self {
            ptr_reg,
            size_reg,
            allow_zero: false,
            null_skips_size_check: false,
        }
    }

    pub(crate) const fn new_nullable(ptr_reg: Reg, size_reg: Reg) -> Self {
        Self {
            ptr_reg,
            size_reg,
            allow_zero: true,
            null_skips_size_check: false,
        }
    }

    pub(crate) const fn new_optional(ptr_reg: Reg, size_reg: Reg) -> Self {
        Self {
            ptr_reg,
            size_reg,
            allow_zero: false,
            null_skips_size_check: true,
        }
    }
}

// ============================================================================
// Pointer-Size Pair Constants
// ============================================================================

pub(crate) mod pairs {
    use super::{MemSizePair, Reg};
    pub static PROBE_READ: [MemSizePair; 1] = [MemSizePair::new_nullable(Reg::R1, Reg::R2)];
    pub static SKB_LOAD_BYTES: [MemSizePair; 1] = [MemSizePair::new(Reg::R3, Reg::R4)];
    pub static SKB_STORE_BYTES: [MemSizePair; 1] = [MemSizePair::new(Reg::R3, Reg::R4)];
    pub static SKB_GET_TUNNEL_KEY: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    pub static SKB_SET_TUNNEL_KEY: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    pub static CSUM_DIFF: [MemSizePair; 2] = [
        MemSizePair::new_nullable(Reg::R1, Reg::R2),
        MemSizePair::new_nullable(Reg::R3, Reg::R4),
    ];
    pub static SK_LOOKUP_TCP: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    pub static SK_LOOKUP_UDP: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    pub static GET_SOCKOPT: [MemSizePair; 1] = [MemSizePair::new(Reg::R4, Reg::R5)];
    pub static GET_TASK_STACK: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    pub static GET_BRANCH_SNAPSHOT: [MemSizePair; 1] = [MemSizePair::new(Reg::R1, Reg::R2)];
    pub static D_PATH: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    pub static SNPRINTF: [MemSizePair; 2] = [
        MemSizePair::new_nullable(Reg::R1, Reg::R2),
        MemSizePair::new_nullable(Reg::R4, Reg::R5),
    ];
    // bpf_redirect_neigh(ifindex, params, plen, flags): R2=params
    // (ARG_PTR_TO_MEM|PTR_MAYBE_NULL|MEM_RDONLY) paired with R3=plen
    // (ARG_CONST_SIZE_OR_ZERO). NULL params => plen must be 0.
    pub static REDIRECT_NEIGH: [MemSizePair; 1] = [MemSizePair::new_nullable(Reg::R2, Reg::R3)];
    // bpf_trace_vprintk(fmt, fmt_size, data, data_len): R3=data
    // (ARG_PTR_TO_MEM|PTR_MAYBE_NULL|MEM_RDONLY) paired with R4=data_len
    // (ARG_CONST_SIZE_OR_ZERO). fmt/fmt_size (R1=ARG_PTR_TO_MEM|MEM_RDONLY,
    // R2=ARG_CONST_SIZE) are bounded by the ConstSize arg kind, exactly
    // like bpf_trace_printk (no explicit pair).
    pub static TRACE_VPRINTK: [MemSizePair; 1] = [MemSizePair::new_nullable(Reg::R3, Reg::R4)];
    // bpf_trace_printk(fmt, fmt_size, ...): R1=fmt (ARG_PTR_TO_MEM|
    // MEM_RDONLY) paired with R2=fmt_size (ARG_CONST_SIZE) — kernel
    // bpf_trace_printk_proto. The kernel walks the fmt buffer
    // (check_mem_size_reg → check_helper_mem_access → check_stack_read)
    // and READ-MARKS its bytes in live stack. Skipping the walk
    // ("ConstSize bounds it, no explicit pair") would leave fmt slots
    // read-dead, letting clean_verifier_state scrub them from cached
    // states and over-merge joins the kernel keeps distinct.
    pub static TRACE_PRINTK: [MemSizePair; 1] = [MemSizePair::new(Reg::R1, Reg::R2)];
    pub static STRNCMP: [MemSizePair; 1] = [MemSizePair::new(Reg::R1, Reg::R2)];
    // ARG_CONST_SIZE_OR_ZERO: kernel admits size=0 (no buffer access),
    // mirrors `bpf_get_stack`'s `ARG_CONST_SIZE_OR_ZERO` flag at the
    // helper proto. The previous `MemSizePair::new` (allow_zero=false)
    // was incorrect — it rejected `bpf_get_stack(ctx, buf, 0, flags)`
    // even though the kernel accepts.
    pub static GET_STACK: [MemSizePair; 1] = [MemSizePair::new_nullable(Reg::R2, Reg::R3)];
    pub static PERF_EVENT_OUTPUT: [MemSizePair; 1] = [MemSizePair::new(Reg::R4, Reg::R5)];
    pub static GET_CURRENT_COMM: [MemSizePair; 1] = [MemSizePair::new(Reg::R1, Reg::R2)];
    // ---- EXCEEDSMAXIMUMKNOWN backlog protos (helper-coverage gaps) ----
    // bpf_lwt_seg6_store_bytes(skb, offset, from, len): R3=from / R4=len.
    pub static LWT_SEG6_STORE_BYTES: [MemSizePair; 1] = [MemSizePair::new(Reg::R3, Reg::R4)];
    // bpf_xdp_store_bytes(xdp, offset, buf, len): R3=buf / R4=len.
    pub static XDP_STORE_BYTES: [MemSizePair; 1] = [MemSizePair::new(Reg::R3, Reg::R4)];
    // bpf_store_hdr_opt(skops, from, len, flags): R2=from / R3=len.
    pub static STORE_HDR_OPT: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    // bpf_sysctl_get_current_value(ctx, buf, buf_len): R2=buf(uninit) / R3=len.
    pub static SYSCTL_GET_CURRENT_VALUE: [MemSizePair; 1] = [MemSizePair::new_nullable(Reg::R2, Reg::R3)];
    // bpf_ima_file_hash(file, dst, size): R2=dst(uninit) / R3=size.
    pub static IMA_FILE_HASH: [MemSizePair; 1] = [MemSizePair::new_nullable(Reg::R2, Reg::R3)];
    // bpf_tcp_{check,gen}_syncookie(sk, iph, iph_len, th, th_len):
    // R2=iph / R3=iph_len and R4=th / R5=th_len.
    pub static TCP_SYNCOOKIE: [MemSizePair; 2] = [
        MemSizePair::new(Reg::R2, Reg::R3),
        MemSizePair::new(Reg::R4, Reg::R5),
    ];
    pub static PERF_EVENT_READ_VALUE: [MemSizePair; 1] = [MemSizePair::new(Reg::R3, Reg::R4)];
    pub static PERF_PROG_READ_VALUE: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];

    // ---- Local-cluster dynptr kfuncs ----
    pub static DYNPTR_FROM_MEM: [MemSizePair; 1] = [MemSizePair::new(Reg::R1, Reg::R2)];
    // size=0 accepted (kernel runtime no-ops on zero-len read/write).
    pub static DYNPTR_READ: [MemSizePair; 1] = [MemSizePair::new_nullable(Reg::R1, Reg::R2)];
    pub static DYNPTR_WRITE: [MemSizePair; 1] = [MemSizePair::new_nullable(Reg::R3, Reg::R4)];

    // ---- Slice cluster ----
    // R3 (`buffer__opt`) is the kernel's `__opt` scratch buffer: NULL is
    // allowed regardless of R4 (the helper just returns NULL when the
    // slow copy path would have been needed).
    pub static DYNPTR_SLICE: [MemSizePair; 1] = [MemSizePair::new_optional(Reg::R3, Reg::R4)];

    // ---- bpf_cpumask_populate(R1=dst, R2=src, R3=src__sz) ----
    pub static CPUMASK_POPULATE: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];

    // ---- bpf_copy_from_user_str(R1=dst, R2=size, R3=unsafe_ptr, R4=flags) ----
    // size=0 accepted (kernel returns 0 / no-op).
    pub static COPY_FROM_USER_STR: [MemSizePair; 1] = [MemSizePair::new_nullable(Reg::R1, Reg::R2)];

    // ---- Helper proto enumeration batch ----
    // bpf_setsockopt(ctx_or_sock, level, optname, optval, optlen): R4/R5
    pub static SETSOCKOPT: [MemSizePair; 1] = [MemSizePair::new(Reg::R4, Reg::R5)];
    // bpf_bind(ctx, addr, addr_len): R2/R3
    pub static BIND: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    // bpf_skb_get_tunnel_opt(ctx, opt, size): R2/R3
    pub static SKB_GET_TUNNEL_OPT: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    // bpf_skb_set_tunnel_opt(ctx, opt, size): R2/R3
    pub static SKB_SET_TUNNEL_OPT: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    // bpf_skb_get_xfrm_state(ctx, index, xfrm, size, flags): R3/R4
    pub static SKB_GET_XFRM_STATE: [MemSizePair; 1] = [MemSizePair::new(Reg::R3, Reg::R4)];
    // bpf_skb_load_bytes_relative(ctx, offset, to, len, start_header): R3/R4
    pub static SKB_LOAD_BYTES_RELATIVE: [MemSizePair; 1] = [MemSizePair::new(Reg::R3, Reg::R4)];
    // bpf_probe_write_user(dst_user, src, size): R2/R3
    pub static PROBE_WRITE_USER: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    // bpf_read_branch_records(ctx, buf, size, flags): R2/R3 (buf may be NULL when size=0)
    pub static READ_BRANCH_RECORDS: [MemSizePair; 1] =
        [MemSizePair::new_nullable(Reg::R2, Reg::R3)];
    // bpf_seq_printf(seq, fmt, fmt_sz, data, data_len): R4/R5 (data nullable when len=0)
    pub static SEQ_PRINTF: [MemSizePair; 1] = [MemSizePair::new_nullable(Reg::R4, Reg::R5)];
    // bpf_seq_write(seq, data, len): R2/R3 (size_or_zero accepted)
    pub static SEQ_WRITE: [MemSizePair; 1] = [MemSizePair::new_nullable(Reg::R2, Reg::R3)];
    // bpf_skb_output(skb, map, flags, data, size): R4/R5 (data size_or_zero accepted)
    pub static SKB_OUTPUT: [MemSizePair; 1] = [MemSizePair::new_nullable(Reg::R4, Reg::R5)];
    // bpf_get_ns_current_pid_tgid(dev, ino, nsdata, size): R3/R4
    pub static GET_NS_CURRENT_PID_TGID: [MemSizePair; 1] = [MemSizePair::new(Reg::R3, Reg::R4)];
    // bpf_sysctl_get_name(ctx, buf, len, flags): R2/R3 (write-only buffer)
    pub static SYSCTL_GET_NAME: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    // bpf_lwt_*_push_encap(ctx, type, hdr, len): R3/R4
    pub static LWT_PUSH_ENCAP: [MemSizePair; 1] = [MemSizePair::new(Reg::R3, Reg::R4)];
    // bpf_lwt_seg6_action(ctx, action, param, param_len): R3/R4
    pub static LWT_SEG6_ACTION: [MemSizePair; 1] = [MemSizePair::new(Reg::R3, Reg::R4)];

    // ---- Helper proto enumeration batch 2 ----
    // bpf_ima_inode_hash(inode, dst, size): R2/R3
    pub static IMA_INODE_HASH: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    // bpf_sys_bpf(cmd, attr, attr_size): R2/R3 (attr is rdonly mem)
    pub static SYS_BPF: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
    // bpf_xdp_load_bytes(ctx, off, buf, len): R3/R4
    pub static XDP_LOAD_BYTES: [MemSizePair; 1] = [MemSizePair::new(Reg::R3, Reg::R4)];
    // bpf_tcp_raw_gen_syncookie_ipv4(iph, th, th_len): R2/R3 (size_or_zero)
    pub static TCP_RAW_GEN_SYNCOOKIE_IPV4: [MemSizePair; 1] =
        [MemSizePair::new_nullable(Reg::R2, Reg::R3)];
    // bpf_tcp_raw_gen_syncookie_ipv6(iph, th, th_len): R2/R3 (size_or_zero)
    pub static TCP_RAW_GEN_SYNCOOKIE_IPV6: [MemSizePair; 1] =
        [MemSizePair::new_nullable(Reg::R2, Reg::R3)];
    // bpf_snprintf_btf(str, str_sz, ptr, ptr_size, flags): R1/R2 + R3/R4
    pub static SNPRINTF_BTF: [MemSizePair; 2] = [
        MemSizePair::new(Reg::R1, Reg::R2),
        MemSizePair::new(Reg::R3, Reg::R4),
    ];
    // bpf_sock_ops_load_hdr_opt(ctx, search, len, flags): R2/R3 (writable)
    pub static LOAD_HDR_OPT: [MemSizePair; 1] = [MemSizePair::new(Reg::R2, Reg::R3)];
}
