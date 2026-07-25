// src/analysis/reg_types.rs
use crate::analysis::machine::frame_stack::FrameLevel;
use crate::analysis::machine::reg::Reg;

pub const NUM_REGS: usize = 11;

/// Orthogonal pointer-type flags, modeled after the kernel's `bpf_type_flag`.
///
/// Kernel layout packs these into the high bits of `enum bpf_reg_type`; we keep
/// them in a dedicated field on variants that need them. New variants added by
/// later phases (dynptr, arena, refcounted kptrs, …) grow a `flags` field on
/// demand — not every variant needs one.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Default)]
pub struct PtrFlags(u16);

impl PtrFlags {
    pub const TRUSTED: PtrFlags = PtrFlags(1 << 0);
    pub const UNTRUSTED: PtrFlags = PtrFlags(1 << 1);
    pub const RCU: PtrFlags = PtrFlags(1 << 2);
    pub const RDONLY: PtrFlags = PtrFlags(1 << 3);
    pub const PERCPU: PtrFlags = PtrFlags(1 << 4);
    pub const MEM_ALLOC: PtrFlags = PtrFlags(1 << 5);
    #[allow(dead_code)]
    pub const NON_OWN_REF: PtrFlags = PtrFlags(1 << 6);
    /// `__user` BTF type tag — kernel pointer addressing user-space memory.
    /// Direct deref is rejected; programs must use `bpf_copy_from_user`.
    /// Set on entry-arg ctx-array slot loads whose attach-target arg has
    /// `__user` in its vmlinux/module BTF (mirrored via a static table
    /// in runner.rs `ATTACH_TARGET_ARG_TAGS`).
    pub const USER: PtrFlags = PtrFlags(1 << 7);

    pub const fn empty() -> Self {
        PtrFlags(0)
    }

    pub const fn contains(self, other: PtrFlags) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: PtrFlags) -> Self {
        PtrFlags(self.0 | other.0)
    }

    pub const fn difference(self, other: PtrFlags) -> Self {
        PtrFlags(self.0 & !other.0)
    }

    #[allow(dead_code)]
    pub const fn bits(self) -> u16 {
        self.0
    }
}

impl std::ops::BitOr for PtrFlags {
    type Output = PtrFlags;
    fn bitor(self, rhs: PtrFlags) -> PtrFlags {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for PtrFlags {
    fn bitor_assign(&mut self, rhs: PtrFlags) {
        self.0 |= rhs.0;
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub enum RegType {
    #[default]
    NotInit,
    ScalarValue,
    PtrToCtx,
    PtrToStack {
        frame_level: FrameLevel,
    },
    PtrToPacket,
    PtrToPacketEnd,
    PtrToPacketMeta,
    PtrToMapObject {
        map_idx: usize,
    },
    PtrToMapValueOrNull {
        id: u32,
        map_idx: usize,
        /// Fresh per-lookup-instance identifier, propagated through
        /// chained lookups. Mirrors kernel `map_uid`. Two map-of-maps
        /// lookups at different keys yield different uids; subsequent
        /// inner-lookups inherit their owner's uid. Cross-arg checks
        /// (bpf_timer_init / bpf_wq_init) compare uids to reject
        /// e.g. timer_mim_reject's `bpf_timer_init(&val->timer,
        /// inner_map2)` where val came from a different inner-map
        /// instance. `None` = "unconstrained" (raw map-decl, ALU
        /// drops, path-merge widening) — never rejects.
        map_uid: Option<u32>,
    },
    PtrToMapValue {
        id: u32,
        offset: Option<i64>,
        map_idx: usize,
        map_uid: Option<u32>,
        /// Read-only marker. Set on R2 of a `bpf_for_each_map_elem`
        /// callback (kernel `set_map_elem_callback_state` stamps
        /// PTR_TO_MAP_KEY on the key arg, distinct from R3's writable
        /// PTR_TO_MAP_VALUE) so writes through it reject. Default
        /// `false` for the standard map-value path; the OrNull /
        /// non-rdonly map-value cluster all keep the standard
        /// writable semantics.
        rdonly: bool,
    },
    PtrToSocket {
        ref_id: Option<u32>,
    },
    PtrToSocketOrNull {
        ref_id: Option<u32>,
    },
    PtrToSockCommon {
        ref_id: Option<u32>,
    },
    PtrToSockCommonOrNull {
        ref_id: Option<u32>,
    },
    PtrToTcpSock {
        id: Option<u32>,
    },
    PtrToTcpSockOrNull {
        id: Option<u32>,
    },
    PtrToBtfId {
        type_name: &'static str,
        flags: PtrFlags,
        /// Optional acquired-reference id, set when the pointer was minted by a
        /// `KF_ACQUIRE` kfunc (e.g. `bpf_get_task_exe_file`,
        /// `bpf_lookup_user_key`, `bpf_kfunc_nested_acquire_*_test`). Released
        /// by the corresponding `KF_RELEASE` kfunc (`bpf_put_file`,
        /// `bpf_key_put`, `bpf_kfunc_nested_release_test`); `None` for
        /// non-acquired BTF pointers (BPF_PROG arg loads, BTF field walks,
        /// `__rcu`/decl-tag-trusted, …) where leak detection isn't tracked.
        ref_id: Option<u32>,
    },
    PtrToBtfIdOrNull {
        id: u32, // For null-tracking across branches
        type_name: &'static str,
        flags: PtrFlags,
        /// See `PtrToBtfId::ref_id`. After a null-check refinement to the
        /// non-null variant the `ref_id` is preserved on the success branch
        /// and dropped on the null branch.
        ref_id: Option<u32>,
    },
    PtrToAllocMemOrNull {
        id: u32,
        mem_size: u64,
        /// Optional ref_id linking this pointer to an owning acquire-tracked
        /// resource (e.g. the source dynptr for a `bpf_dynptr_data` slice).
        /// When the owning ref is released, `invalidate_ref` rewrites this
        /// register to `ScalarValue`, catching use-after-release on slice
        /// pointers obtained from a released dynptr.
        ref_id: Option<u32>,
        /// Source dynptr identity for slice pointers (mirrors kernel
        /// `bpf_reg_state::dynptr_id`). Set on the `PtrToAllocMem*`
        /// returned by `bpf_dynptr_data` for *any* dynptr kind
        /// (including unrefcounted `Local`); `None` for non-slice
        /// allocations. On dynptr overwrite, `validate_dynptr_arg`
        /// sweeps regs + slots demoting matches to `ScalarValue` —
        /// catches use-after-reinit even when `ref_id` is None.
        dynptr_id: Option<u32>,
        /// Read-only marker for the underlying allocation. Set by
        /// `bpf_dynptr_slice` (kernel returns `const void *` regardless
        /// of source-dynptr rdonly bit) so subsequent stores reject
        /// with "cannot write into rdonly_mem". `bpf_dynptr_slice_rdwr`
        /// keeps `false`; default `false` for non-slice paths.
        rdonly: bool,
    },
    PtrToAllocMem {
        id: u32,
        mem_size: u64,
        ref_id: Option<u32>,
        dynptr_id: Option<u32>,
        rdonly: bool,
    },
    /// Refcounted pointer to a `struct bpf_cpumask`. Mirrors
    /// `PtrToSocket` ref-tracking: `bpf_cpumask_create` mints a fresh
    /// `ref_id` on the OrNull form; null-check refinement promotes to
    /// the non-null form on the success branch and drops the ref on
    /// the null branch; `bpf_cpumask_release` consumes the ref.
    PtrToCpumask {
        ref_id: Option<u32>,
    },
    PtrToCpumaskOrNull {
        ref_id: Option<u32>,
    },
    /// Bounded pointer to memory allocated from a BPF arena.
    /// `bpf_arena_alloc_pages` mints a fresh `ref_id` on the OrNull form
    /// with `mem_size = page_cnt * PAGE_SIZE`; null-check refinement
    /// promotes to the non-null form on the success branch and drops the
    /// ref on the null branch; `bpf_arena_free_pages` consumes the ref.
    /// Memory access through the non-null form is bounds-checked against
    /// `mem_size`, mirroring `PtrToAllocMem`.
    PtrToArena {
        ref_id: Option<u32>,
        mem_size: u64,
    },
    PtrToArenaOrNull {
        ref_id: Option<u32>,
        mem_size: u64,
    },
    /// Refcounted pointer to a `struct cgroup`. Mirrors
    /// the cpumask family acquire/release pattern. `bpf_cgroup_from_id`
    /// mints a fresh `ref_id` on the OrNull form; null-check refinement
    /// promotes to the non-null form on the success branch and drops the
    /// ref on the null branch; `bpf_cgroup_release` consumes the ref.
    /// `bpf_cgroup_acquire` mints a new ref on an existing pointer.
    PtrToCgroup {
        ref_id: Option<u32>,
    },
    PtrToCgroupOrNull {
        ref_id: Option<u32>,
    },
    /// Pointer to a `struct task_struct`. Mirrors the
    /// cgroup family acquire/release/null-check pattern. Minted by
    /// `bpf_get_current_task_btf` (no acquire — kernel-trusted current
    /// pointer), `bpf_task_acquire`, `bpf_task_from_pid` (the latter
    /// two with KF_ACQUIRE | KF_RET_NULL); released by
    /// `bpf_task_release`. Accepted as `R2` of `bpf_task_storage_get/_delete`.
    PtrToTask {
        ref_id: Option<u32>,
    },
    PtrToTaskOrNull {
        ref_id: Option<u32>,
    },
    /// Refcounted pointer to a heap-allocated kernel object.
    /// Minted by `bpf_obj_new_impl` / `bpf_refcount_acquire_impl` and by
    /// list/rbtree pop kfuncs; consumed by `bpf_obj_drop_impl` and by
    /// list/rbtree push kfuncs (which transfer ownership into the
    /// container). One unified variant covers list_node / rb_node /
    /// generic kptr in this lite scope; future precision can branch on
    /// btf_id.
    PtrToOwnedKptr {
        ref_id: Option<u32>,
        /// Signed byte-offset within the allocated object. Bumped by
        /// `Add reg, K` / `Sub reg, K` (kernel `verifier.c` v6.15
        /// ~L15170 preserves PTR_TO_BTF_ID|MEM_ALLOC through pointer
        /// arithmetic and propagates `reg->off`). `bpf_obj_drop` /
        /// `bpf_kptr_xchg` reject non-zero offsets ("R1 must have zero
        /// offset when passed to release func" — verifier.c ~L13242).
        offset: i32,
        /// `NON_OWN_REF` flag (verifier.c v6.15 L12450 `ref_set_non_owning`).
        /// Set after `bpf_rbtree_add` / `bpf_list_push_*` consumes the
        /// owning ref; the original aliases keep their type but lose
        /// `ref_id`. Non-owning refs are invalidated on `bpf_spin_unlock`
        /// (verifier.c L8382 `invalidate_non_owning_refs`).
        non_owning: bool,
        /// Local-BTF type id of the allocated struct (the type passed to
        /// `bpf_obj_new(typeof(*x))`, or copied from the source through
        /// `bpf_refcount_acquire` / list/rbtree pop kfuncs). `None` when
        /// the source kfunc didn't surface a type id (e.g. lite-scope
        /// `bpf_rbtree_first` whose `__contains` head BTF id is not yet
        /// threaded through). Consumed by the `__contains` cross-arg
        /// validator on `bpf_list_push_*` / `bpf_rbtree_add` to reject
        /// type-mismatched node pushes (kernel verifier.c v6.15 L13160
        /// `ref_btf_id != ds_head->ds_data->btf_id`).
        pointee_btf_id: Option<u32>,
    },
    PtrToOwnedKptrOrNull {
        ref_id: Option<u32>,
        pointee_btf_id: Option<u32>,
        /// Mirrors `PtrToOwnedKptr.offset` so the offset survives across
        /// the null-check refinement. Graph-pop kfuncs
        /// (`bpf_list_pop_*`/`bpf_rbtree_first`/`bpf_rbtree_remove`)
        /// initialize this to the parent struct's `node_offset` so the
        /// post-null-check `PtrToOwnedKptr` matches the kernel's
        /// `reg->btf_id = parent_struct + reg->off = node_offset`
        /// model — the `__contains` cross-arg check at the next push/add
        /// then sees the correct offset.
        offset: i32,
    },
    /// Pointer loaded from a kptr field of a map value. The four kptr
    /// flavors (`__kptr_untrusted`, `__kptr`, `__rcu`, `__percpu_kptr`)
    /// are encoded by `flags`, mirroring the kernel's
    /// `PTR_TO_BTF_ID | MEM_*` flag scheme:
    ///   - `Unref`   → `UNTRUSTED`
    ///   - `Ref`     → `MEM_ALLOC` (trusted, refcounted; deref OK)
    ///   - `Rcu`     → `RCU`       (deref OK while in `bpf_rcu_read_lock`)
    ///   - `Percpu`  → `PERCPU`    (must pass through `bpf_*_cpu_ptr` first)
    /// `pointee_btf_id` is the inner struct's BTF id (from the map's
    /// BTF), used for type-matching in `bpf_kptr_xchg` and pointee-bounds
    /// checks on deref. `ref_id` is set only when the pointer has been
    /// taken out of the map via `bpf_kptr_xchg` (the prior contents),
    /// participating in the existing reference-tracking machinery; loads
    /// that don't transfer ownership leave it `None`.
    PtrToMapKptr {
        pointee_btf_id: u32,
        ref_id: Option<u32>,
        flags: PtrFlags,
        /// Signed byte-offset within the kptr's pointee struct. Bumped by
        /// `Add reg, K` / `Sub reg, K` (kernel `verifier.c` v6.15 ~L15170
        /// preserves PTR_TO_BTF_ID|MEM_* through pointer arithmetic and
        /// propagates `reg->off`). Required for the
        /// `R6 = bpf_kptr_xchg(...); R1 = R6 + 16; bpf_kptr_xchg(R1, NULL)`
        /// idiom (second xchg aimed at a kptr field embedded inside the
        /// previously xchg'd object — `local_kptr_stash::unstash_rb_node`).
        /// Release sinks (`bpf_obj_drop`, `bpf_kptr_xchg` arg1) reject
        /// non-zero offsets in the post-call gate.
        offset: i32,
    },
    PtrToMapKptrOrNull {
        pointee_btf_id: u32,
        ref_id: Option<u32>,
        flags: PtrFlags,
        /// Mirrors `PtrToMapKptr.offset` so the offset survives across
        /// the null-check refinement (`to_non_null` round-trips it).
        offset: i32,
    },
    /// Pointer to a callback subprogram, produced by `LD_IMM64 BPF_PSEUDO_FUNC`
    /// . Consumed by callback-taking helpers (`bpf_loop`,
    /// `bpf_for_each_map_elem`, `bpf_timer_set_callback`) and by the
    /// `bpf_set_exception_callback` kfunc to register an exception handler.
    /// Not dereferenceable as data; arithmetic on it produces a scalar.
    PtrToCallback {
        subprog_pc: u32,
    },
    /// Kernel-managed dynptr pointer (kernel `PTR_TO_DYNPTR`).
    /// Distinct from a stack-based dynptr (which is `PtrToStack` aimed
    /// at a `DynptrSlot`). Synthesized for the `bpf_user_ringbuf_drain`
    /// cb's R1 (kernel `set_user_ringbuf_callback_state`,
    /// verifier.c v6.15 ~L10800). Accepted by dynptr consumers
    /// (`bpf_dynptr_data`, `_read`); rejected by the
    /// `validate_dynptr_arg` `uninit:true` branch (constructors)
    /// and by the `rdwr_only` branch when `rdonly` is set
    /// (`bpf_dynptr_write`). Not dereferenceable as data — load/store
    /// fall through to `UnsafeGenericLoad`/`Store` ("invalid mem access
    /// 'dynptr_ptr'", verifier.c v6.15 ~L7400 `check_mem_access`).
    /// Pointer arithmetic demotes to scalar (kernel rejects "dereference
    /// of modified dynptr_ptr ptr").
    PtrToDynptr {
        kind: crate::analysis::machine::stack_state::DynptrKind,
        rdonly: bool,
    },
}

impl RegType {
    pub fn is_pointer(self) -> bool {
        !self.is_scalar()
    }

    // Pointers that will experience null checks or the result of null checks
    pub fn is_null_checked(self) -> bool {
        use RegType::*;
        matches!(
            self,
            PtrToMapValueOrNull { .. }
                | PtrToSocketOrNull { .. }
                | PtrToSockCommonOrNull { .. }
                | PtrToTcpSockOrNull { .. }
                | PtrToCpumaskOrNull { .. }
                | PtrToArenaOrNull { .. }
                | PtrToCgroupOrNull { .. }
                | PtrToTaskOrNull { .. }
                | PtrToOwnedKptrOrNull { .. }
                | PtrToMapKptrOrNull { .. }
                | PtrToMapValue { .. }
                | PtrToSocket { .. }
                | PtrToSockCommon { .. }
                | PtrToTcpSock { .. }
                | PtrToCpumask { .. }
                | PtrToArena { .. }
                | PtrToCgroup { .. }
                | PtrToTask { .. }
                | PtrToOwnedKptr { .. }
                | PtrToMapKptr { .. }
        ) || matches!(
            self,
            // Acquire-tracked PtrToBtfId (`ref_id: Some`) is the
            // promoted, post-null-check form of `PtrToBtfIdOrNull`
            // minted by an ACQUIRE-flagged kfunc returning
            // `RetKind::PtrToBtfIdNamed` (e.g. `bpf_testmod_ctx_create`).
            // Kernel guarantees non-null after the program's explicit
            // null check; treat as null-checked so `condition_outcome`
            // resolves a redundant `==0` test as dead, preventing the
            // dead-branch from leaking the live ref into the exit-time
            // unreleased-reference check (kfunc_call_test::kfunc_call_ctx).
            //
            // Restrict to `ref_id: Some` to preserve the legitimate
            // null-feasibility of UNTRUSTED PtrToBtfId from struct-field
            // loads (which the kernel can dereference via PROBE_MEM but
            // which the program may legitimately null-check, e.g.
            // `task->real_parent` in rcu_read_lock::non_sleepable_rcu_mismatch).
            RegType::PtrToBtfId {
                ref_id: Some(_),
                ..
            }
        )
    }

    pub fn is_scalar(self) -> bool {
        use RegType::*;
        matches!(self, ScalarValue | NotInit)
    }

    /// Returns the non-null version of a nullable pointer type
    #[allow(clippy::wrong_self_convention)]
    pub fn to_non_null(&self) -> Option<RegType> {
        match *self {
            RegType::PtrToMapValueOrNull {
                id,
                map_idx,
                map_uid,
            } => Some(RegType::PtrToMapValue {
                offset: Some(0),
                map_idx,
                id,
                map_uid,
                rdonly: false,
            }),
            RegType::PtrToSocketOrNull { ref_id: id } => Some(RegType::PtrToSocket { ref_id: id }),
            RegType::PtrToSockCommonOrNull { ref_id: id } => {
                Some(RegType::PtrToSockCommon { ref_id: id })
            }
            RegType::PtrToTcpSockOrNull { id } => Some(RegType::PtrToTcpSock { id }),
            RegType::PtrToCpumaskOrNull { ref_id } => Some(RegType::PtrToCpumask { ref_id }),
            RegType::PtrToArenaOrNull { ref_id, mem_size } => {
                Some(RegType::PtrToArena { ref_id, mem_size })
            }
            RegType::PtrToCgroupOrNull { ref_id } => Some(RegType::PtrToCgroup { ref_id }),
            RegType::PtrToTaskOrNull { ref_id } => Some(RegType::PtrToTask { ref_id }),
            RegType::PtrToOwnedKptrOrNull {
                ref_id,
                pointee_btf_id,
                offset,
            } => Some(RegType::PtrToOwnedKptr {
                ref_id,
                offset,
                non_owning: false,
                pointee_btf_id,
            }),
            RegType::PtrToMapKptrOrNull {
                pointee_btf_id,
                ref_id,
                flags,
                offset,
            } => Some(RegType::PtrToMapKptr {
                pointee_btf_id,
                ref_id,
                flags,
                offset,
            }),
            RegType::PtrToBtfIdOrNull {
                id: _,
                type_name,
                flags,
                ref_id,
            } => Some(RegType::PtrToBtfId {
                type_name,
                flags,
                ref_id,
            }),
            _ => None,
        }
    }

    /// Check if this is a nullable pointer type
    pub fn is_nullable(&self) -> bool {
        matches!(
            self,
            RegType::PtrToMapValueOrNull { .. }
                | RegType::PtrToSocketOrNull { .. }
                | RegType::PtrToSockCommonOrNull { .. }
                | RegType::PtrToTcpSockOrNull { .. }
                | RegType::PtrToCpumaskOrNull { .. }
                | RegType::PtrToArenaOrNull { .. }
                | RegType::PtrToCgroupOrNull { .. }
                | RegType::PtrToTaskOrNull { .. }
                | RegType::PtrToOwnedKptrOrNull { .. }
                | RegType::PtrToMapKptrOrNull { .. }
                | RegType::PtrToBtfIdOrNull { .. }
        )
    }

    pub fn get_ptr_offset(&self) -> Option<i64> {
        match *self {
            RegType::PtrToMapValue {
                offset, map_idx: _, ..
            } => offset,
            RegType::PtrToOwnedKptr { offset, .. } => Some(offset as i64),
            RegType::PtrToMapKptr { offset, .. } => Some(offset as i64),
            _ => None,
        }
    }

    /// Helper to check strict type compatibility
    pub fn is_same_pointer_type(t1: &RegType, t2: &RegType) -> bool {
        // Discriminant check ensures we don't mix PtrToMap with PtrToStack.
        // For PtrToMap*, we also check if they point to the SAME map_idx.
        match (t1, t2) {
            (
                RegType::PtrToMapObject { map_idx: id1, .. },
                RegType::PtrToMapObject { map_idx: id2, .. },
            ) => id1 == id2,
            (
                RegType::PtrToMapValue { map_idx: id1, .. },
                RegType::PtrToMapValue { map_idx: id2, .. },
            ) => id1 == id2,
            _ => std::mem::discriminant(t1) == std::mem::discriminant(t2),
        }
    }

    pub fn is_packet_ptr(&self) -> bool {
        matches!(
            self,
            RegType::PtrToPacket | RegType::PtrToPacketEnd | RegType::PtrToPacketMeta
        )
    }

    /// Returns the flag set for variants that carry one, else empty.
    pub fn ptr_flags(&self) -> PtrFlags {
        match *self {
            RegType::PtrToBtfId { flags, .. } | RegType::PtrToBtfIdOrNull { flags, .. } => flags,
            RegType::PtrToMapKptr { flags, .. } | RegType::PtrToMapKptrOrNull { flags, .. } => {
                flags
            }
            _ => PtrFlags::empty(),
        }
    }

    /// True when the pointer is known-trusted (kfunc return, ctx trusted field, …).
    /// Preserves the meaning of the former `trusted: bool` field.
    pub fn is_trusted(&self) -> bool {
        self.ptr_flags().contains(PtrFlags::TRUSTED)
    }

    #[allow(dead_code)]
    pub fn is_untrusted(&self) -> bool {
        self.ptr_flags().contains(PtrFlags::UNTRUSTED)
    }

    /// Returns the ref_id if this type holds a reference
    pub fn get_ref_id(&self) -> Option<u32> {
        match *self {
            RegType::PtrToSocket { ref_id: id }
            | RegType::PtrToSocketOrNull { ref_id: id }
            | RegType::PtrToSockCommon { ref_id: id }
            | RegType::PtrToSockCommonOrNull { ref_id: id }
            | RegType::PtrToTcpSock { id }
            | RegType::PtrToTcpSockOrNull { id }
            | RegType::PtrToCpumask { ref_id: id }
            | RegType::PtrToCpumaskOrNull { ref_id: id }
            | RegType::PtrToArena { ref_id: id, .. }
            | RegType::PtrToArenaOrNull { ref_id: id, .. }
            | RegType::PtrToCgroup { ref_id: id }
            | RegType::PtrToCgroupOrNull { ref_id: id }
            | RegType::PtrToTask { ref_id: id }
            | RegType::PtrToTaskOrNull { ref_id: id } => id,
            RegType::PtrToOwnedKptrOrNull { ref_id, .. } => ref_id,
            RegType::PtrToOwnedKptr { ref_id, .. } => ref_id,
            RegType::PtrToBtfId { ref_id, .. } | RegType::PtrToBtfIdOrNull { ref_id, .. } => ref_id,
            RegType::PtrToMapKptr { ref_id, .. } | RegType::PtrToMapKptrOrNull { ref_id, .. } => {
                ref_id
            }
            RegType::PtrToAllocMem { ref_id, .. } | RegType::PtrToAllocMemOrNull { ref_id, .. } => {
                ref_id
            }
            _ => None,
        }
    }
}

// For general pointers
pub fn new_ptr_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static PACKET_ID_COUNTER: AtomicU32 = AtomicU32::new(1);
    PACKET_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

// For references (return values of special helper functions)
pub fn new_ref_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static REF_ID_COUNTER: AtomicU32 = AtomicU32::new(1);
    REF_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Fresh per-lookup map_uid (kernel: each map-of-maps lookup result
/// gets a distinct uid). Zero is reserved for "no uid"; the first
/// minted is 1.
pub fn new_map_uid() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static MAP_UID_COUNTER: AtomicU32 = AtomicU32::new(1);
    MAP_UID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Fresh identity token for a scalar value. Two registers/slots that share
/// an id represent the same underlying unknown scalar, so refining one
/// (e.g. via a conditional) can be propagated to the others.
pub fn new_scalar_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SCALAR_ID_COUNTER: AtomicU32 = AtomicU32::new(1);
    SCALAR_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Fresh identity token for an open-coded iterator.
/// Minted at `*_new` time and stored on the iterator's stack slot.
/// Subsumption matches states by this id to recognize "same
/// iterator loop" across revisits.
pub fn new_iter_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static ITER_ID_COUNTER: AtomicU32 = AtomicU32::new(1);
    ITER_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Fresh identity token for a dynptr instance. Minted at construction
/// (`bpf_dynptr_from_mem`, `bpf_ringbuf_reserve_dynptr`,
/// `bpf_dynptr_from_skb`, `bpf_dynptr_from_xdp`) and stamped on both
/// pair slots. Slices returned by `bpf_dynptr_data` carry this id on
/// the result `PtrToAllocMem*`. On dynptr overwrite/release, all regs
/// + spilled slots whose `PtrToAllocMem*` carries the matching id are
/// demoted to `ScalarValue` — mirrors kernel `verifier.c` v6.15
/// `bpf_for_each_reg_in_vstate { if (dreg->dynptr_id == id) ... }`
/// at L913-919 inside `destroy_if_dynptr_stack_slot`. Distinct from
/// `ref_id` (acquire-tracked release id) so unrefcounted dynptrs
/// (`Local`/`Skb`/`Xdp`, `ref_id == 0`) still get slice tracking.
pub fn new_dynptr_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static DYNPTR_ID_COUNTER: AtomicU32 = AtomicU32::new(1);
    DYNPTR_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Fresh id for an IRQ-flag stack slot at acquire (kernel
/// `++env->id_gen` reused for `state->active_irq_id`).
pub fn new_irq_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static IRQ_ID_COUNTER: AtomicU32 = AtomicU32::new(1);
    IRQ_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Classify types into families. Pointer and pointer-or-null variants
/// of the same kind share a family (e.g. PtrToMapValue and PtrToMapValueOrNull).
pub fn type_family(ty: &RegType) -> u8 {
    use RegType::*;
    match ty {
        NotInit => 0,
        ScalarValue => 1,
        PtrToCtx => 2,
        PtrToStack { .. } => 3,
        PtrToMapValue { .. } | PtrToMapValueOrNull { .. } => 4,
        PtrToMapObject { .. } => 5,
        PtrToPacket => 6,
        PtrToPacketEnd => 7,
        PtrToPacketMeta => 8,
        PtrToSocket { .. } | PtrToSocketOrNull { .. } => 9,
        PtrToSockCommon { .. } | PtrToSockCommonOrNull { .. } => 10,
        PtrToTcpSock { .. } | PtrToTcpSockOrNull { .. } => 11,
        PtrToBtfId { .. } | PtrToBtfIdOrNull { .. } => 12,
        PtrToAllocMem { .. } | PtrToAllocMemOrNull { .. } => 13,
        PtrToCallback { .. } => 14,
        PtrToCpumask { .. } | PtrToCpumaskOrNull { .. } => 15,
        PtrToArena { .. } | PtrToArenaOrNull { .. } => 16,
        PtrToOwnedKptr { .. } | PtrToOwnedKptrOrNull { .. } => 17,
        PtrToCgroup { .. } | PtrToCgroupOrNull { .. } => 18,
        PtrToTask { .. } | PtrToTaskOrNull { .. } => 19,
        PtrToMapKptr { .. } | PtrToMapKptrOrNull { .. } => 20,
        PtrToDynptr { .. } => 21,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeState {
    pub regs: [RegType; NUM_REGS],
}

impl TypeState {
    pub fn new_not_init() -> Self {
        Self {
            regs: [RegType::NotInit; NUM_REGS],
        }
    }

    pub fn get(&self, r: Reg) -> RegType {
        if let Some(i) = crate::analysis::machine::reg::reg_to_index(r) {
            self.regs[i]
        } else {
            RegType::NotInit
        }
    }

    pub fn set(&mut self, r: Reg, ty: RegType) {
        if let Some(i) = crate::analysis::machine::reg::reg_to_index(r) {
            self.regs[i] = ty;
        }
    }

    pub fn reg_types_str(&self) -> String {
        let mut s = String::new();
        for (i, ty) in self.regs.iter().enumerate() {
            s.push_str(&format!("R{}: {:?} ", i, ty));
        }
        s
    }
}

impl Default for TypeState {
    fn default() -> Self {
        Self::new_not_init()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptr_flags_empty_and_contains() {
        let e = PtrFlags::empty();
        assert!(!e.contains(PtrFlags::TRUSTED));
        assert!(!e.contains(PtrFlags::UNTRUSTED));
        assert_eq!(e.bits(), 0);
    }

    #[test]
    fn ptr_flags_union_and_contains() {
        let f = PtrFlags::TRUSTED | PtrFlags::RCU;
        assert!(f.contains(PtrFlags::TRUSTED));
        assert!(f.contains(PtrFlags::RCU));
        assert!(!f.contains(PtrFlags::UNTRUSTED));
        assert!(f.contains(PtrFlags::TRUSTED | PtrFlags::RCU));
    }

    #[test]
    fn ptr_flags_difference() {
        let f = PtrFlags::TRUSTED | PtrFlags::RCU;
        let d = f.difference(PtrFlags::RCU);
        assert!(d.contains(PtrFlags::TRUSTED));
        assert!(!d.contains(PtrFlags::RCU));
    }

    #[test]
    fn reg_type_is_trusted_matches_flag() {
        let trusted = RegType::PtrToBtfId {
            type_name: "x",
            flags: PtrFlags::TRUSTED,
            ref_id: None,
        };
        let untrusted = RegType::PtrToBtfId {
            type_name: "x",
            flags: PtrFlags::UNTRUSTED,
            ref_id: None,
        };
        let empty = RegType::PtrToBtfId {
            type_name: "x",
            flags: PtrFlags::empty(),
            ref_id: None,
        };
        assert!(trusted.is_trusted());
        assert!(!trusted.is_untrusted());
        assert!(untrusted.is_untrusted());
        assert!(!untrusted.is_trusted());
        assert!(!empty.is_trusted());
        assert!(!empty.is_untrusted());
    }

    #[test]
    fn reg_type_is_trusted_false_for_non_btf_variants() {
        assert!(!RegType::ScalarValue.is_trusted());
        assert!(!RegType::PtrToCtx.is_trusted());
        assert!(
            !RegType::PtrToMapValue {
                id: 1,
                offset: None,
                map_idx: 0,
                map_uid: None,
                rdonly: false,
            }
            .is_trusted()
        );
    }

    #[test]
    fn map_kptr_or_null_to_non_null_round_trip() {
        let n = RegType::PtrToMapKptrOrNull {
            pointee_btf_id: 12,
            ref_id: Some(7),
            flags: PtrFlags::UNTRUSTED,
            offset: 0,
        };
        assert!(n.is_nullable());
        assert!(n.is_null_checked());
        assert_eq!(n.get_ref_id(), Some(7));
        assert!(n.is_untrusted());
        let nn = n.to_non_null().expect("convertible");
        assert!(matches!(
            nn,
            RegType::PtrToMapKptr {
                pointee_btf_id: 12,
                ref_id: Some(7),
                ..
            }
        ));
        assert_eq!(type_family(&n), type_family(&nn));
    }

    #[test]
    fn reg_type_equality_distinguishes_flags() {
        let a = RegType::PtrToBtfId {
            type_name: "x",
            flags: PtrFlags::TRUSTED,
            ref_id: None,
        };
        let b = RegType::PtrToBtfId {
            type_name: "x",
            flags: PtrFlags::UNTRUSTED,
            ref_id: None,
        };
        assert_ne!(
            a, b,
            "flags must participate in PartialEq to preserve old trusted-bool semantics"
        );
    }
}
