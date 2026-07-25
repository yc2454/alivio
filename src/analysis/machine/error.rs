use crate::analysis::flow::subprog::SubprogError;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::ast::ProgramKind;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum VerificationError {
    StackOutOfBounds {
        pc: usize,
        off: i64,
        size: i64,
    },
    PointerOutOfBounds {
        pc: usize,
    },
    UninitializedStackRead {
        pc: usize,
        offset: i64,
    },
    InvalidStackRead {
        pc: usize,
        offset: i64,
    },
    UnsafePacketLoad {
        pc: usize,
        off: i16,
        size: i64,
    },
    UnsafePacketStore {
        pc: usize,
        off: i16,
        size: i64,
    },
    IllegalPacketStore {
        pc: usize,
        off: i16,
        size: i64,
    },
    UnsafeMapLoad {
        pc: usize,
        off: i64,
        size: i64,
        limit: i64,
    },
    UnsafeMapStore {
        pc: usize,
        off: i64,
        size: i64,
        limit: i64,
    },
    UnsafeMemoryStore {
        pc: usize,
        base: Reg,
        off: i16,
        size: i64,
    },
    UnsafeMemoryLoad {
        pc: usize,
        base: Reg,
        off: i16,
        size: i64,
    },
    MapStoreForbidden {
        pc: usize,
        map_idx: usize,
    },
    MapLoadForbidden {
        pc: usize,
        map_idx: usize,
    },
    UnsafeMapAccess {
        pc: usize,
        map_idx: usize,
        size: i64,
    },
    UnsafeGenericLoad {
        pc: usize,
        base: Reg,
        off: i16,
        base_type: RegType,
    },
    UnsafeMemoryRegionLoad {
        pc: usize,
        base: Reg,
        off: i16,
    },
    UnsafeCtxAccess {
        pc: usize,
        off: i16,
        size: i64,
    },
    UnsafeGenericStore {
        pc: usize,
        base: Reg,
        off: i16,
        base_type: RegType,
    },
    UnsafeSocketAccess {
        pc: usize,
        off: i16,
        size: i64,
    },
    DbmInconsistent {
        pc: usize,
    },
    ComplexityLimitExceeded {
        limit: usize,
    },
    InfiniteLoopDetected {
        pc: usize,
    },
    RegisterNotReadable {
        pc: usize,
        reg: Reg,
    },
    RegisterNotWritable {
        pc: usize,
        reg: Reg,
    },
    CfgError(String),
    DivideByZero {
        pc: usize,
    },
    InvalidArgType {
        pc: usize,
        reg: Reg,
    },
    InvalidPointerArithmetic {
        pc: usize,
    },
    InvalidBPFLoadImmInsn {
        pc: usize,
    },
    MapNotFound {
        pc: usize,
        map_idx: usize,
    },
    BackEdge {
        pc: usize,
        target: usize,
    },
    MaxCallDepthExceeded {
        pc: usize,
    },
    MisalignedAccess {
        pc: usize,
        off: i64,
    },
    InvalidReturnCode {
        pc: usize,
    },
    MisalignedPacketAccess {
        pc: usize,
        off: i16,
        size: i64,
    },
    InvalidRegisterTypeState {
        pc: usize,
    },
    RegisterTypeConflict {
        pc: usize,
        reg: Reg,
        old: RegType,
        new: RegType,
    },
    UnreleasedReference,
    UnreleasedIterator,
    UnreleasedDynptr,
    DynptrOverwrite {
        pc: usize,
        off: i64,
    },
    IteratorOverwrite {
        pc: usize,
        off: i64,
    },
    /// Stack write overlapped an active IRQ-flag slot. Mirrors kernel
    /// "expected an initialized irq flag" produced when the slot's
    /// `STACK_IRQ_FLAG` mark is destroyed by a direct write before
    /// `bpf_local_irq_restore` runs.
    IrqFlagOverwrite {
        pc: usize,
        off: i64,
    },
    /// IRQ-related kfunc rejected: arg slot type mismatch, LIFO order
    /// violation, or BPF_EXIT inside an active IRQ region.
    IrqState {
        pc: usize,
        reason: String,
    },
    /// Map-value access landed on a kptr field with a size other than
    /// `BPF_DW` (8 bytes). Kernel: "kptr access size must be BPF_DW".
    KptrAccessSizeMustBeDW {
        pc: usize,
        off: i64,
        size: i64,
    },
    /// Map-value access partially overlaps a kptr field at an offset
    /// other than the field's own (8-byte-aligned) offset. Kernel:
    /// "kptr access misaligned expected=8 off=N".
    KptrAccessMisaligned {
        pc: usize,
        off: i64,
        expected: u8,
    },
    /// Variable-offset map-value access into a map whose value contains
    /// kptr fields. Kernel: "kptr access cannot have variable offset".
    KptrAccessVariableOffset {
        pc: usize,
        map_idx: usize,
    },
    /// Direct store to a referenced kptr slot (`__kptr` / `__rcu` /
    /// `percpu_kptr`). Mutation must go through `bpf_kptr_xchg`.
    /// Kernel: "store to referenced kptr disallowed".
    KptrStoreToReferenced {
        pc: usize,
        off: i64,
    },
    /// Store to a `__uptr` field of a map value. The pointer is
    /// userspace-owned; BPF programs may read it but must not write.
    /// Kernel: "store to uptr disallowed".
    UptrStoreDisallowed {
        pc: usize,
        off: i64,
    },
    InvalidBtfType,
    LockAlreadyHeld {
        pc: usize,
    },
    LockNotHeld {
        pc: usize,
    },
    UnreleasedLock,
    /// `bpf_rcu_read_unlock` called outside an RCU read-side section.
    RcuReadNotHeld {
        pc: usize,
    },
    /// Helper / kfunc marked `CallFlags::RCU` invoked while
    /// `state.rcu_read_depth == 0`.
    NotInRcuReadSection {
        pc: usize,
        helper: u32,
    },
    /// Program exit reached with one or more open RCU read-side sections.
    UnreleasedRcuRead,
    /// Helper / kfunc marked `CallFlags::MIGHT_SLEEP` invoked while
    /// `state.active_preempt_locks > 0`. Mirrors kernel verifier.c
    /// v6.15 ~L11299 / ~L13565.
    SleepableInPreemptDisabled {
        pc: usize,
        helper: u32,
    },
    /// Helper / kfunc marked `CallFlags::MIGHT_SLEEP` invoked inside
    /// an explicit `bpf_rcu_read_lock` critical section. Mirrors kernel
    /// verifier.c v6.15 L13549 ("kernel func is sleepable within
    /// rcu_read_lock region"). Implicit-RCU-at-entry for kprobe/tp/
    /// raw_tp/perf_event is excluded — those go through other gates.
    SleepableInRcuReadSection {
        pc: usize,
        helper: u32,
    },
    /// `bpf_preempt_enable` invoked with no matching disable.
    PreemptNotDisabled {
        pc: usize,
    },
    /// Main-prog `BPF_EXIT` reached inside a preempt-disabled region.
    /// Mirrors kernel verifier.c v6.15 ~L11096.
    ExitInPreemptDisabled,
    /// `bpf_tail_call` invoked inside a preempt-disabled region.
    /// Mirrors kernel verifier.c v6.15 ~L11096.
    TailCallInPreemptDisabled {
        pc: usize,
    },
    /// Helper / kfunc marked `CallFlags::SPIN_LOCK_HELD` invoked
    /// without an active spin_lock. rbtree / list mutators
    /// require a held lock to prevent races on the per-map-value
    /// head/root.
    NotInSpinLockSection {
        pc: usize,
        helper: u32,
    },
    LoadAbsUnderLock {
        pc: usize,
    },
    RelocationInfoMissing {
        pc: usize,
    },
    SubprogError {
        e: SubprogError,
    },
    CannotReturnStackPointer {
        pc: usize,
    },
    SpillToCaller {
        pc: usize,
    },
    HelperNotAllowedForProgram {
        pc: usize,
        helper: u32,
        kind: ProgramKind,
    },
    /// Kernel `check_map_prog_compatibility` (verifier.c L19910): a map
    /// referenced by the prog has a record-field (BPF_SPIN_LOCK,
    /// BPF_TIMER, BPF_LIST_HEAD, BPF_RB_ROOT) that's incompatible with
    /// the program kind. Tracing prog types (kprobe, tracepoint,
    /// raw_tp[_writable], perf_event) cannot use any of these; socket
    /// filter cannot use spin_lock. Reported at program load — no PC.
    MapProgIncompat {
        map_name: String,
        field: &'static str,
        kind: ProgramKind,
    },
    /// LSM attach hook is on the kernel's disabled list
    /// (`getprocattr`, `setprocattr`, `ismaclabel`, `module_request`, ...).
    /// Reported at program load — there is no instruction PC.
    NoreturnAttachTarget {
        target: String,
    },
    /// Tracing prog (fentry/fexit/fmod_ret/raw_tp) attaches to a kernel
    /// function on the BPF helper attach-deny list (e.g. bpf_spin_lock,
    /// bpf_spin_unlock). Kernel rejects at attach, not load — but our
    /// verifier collapses both into the per-prog outcome so this fires
    /// at static SEC validation. Mirrors `tracing_failure.c`.
    TracingAttachDenied {
        target: String,
    },
    /// struct_ops program SEC names a member that the registering kernel
    /// module marks as unsupported (e.g. bpf_testmod_ops.unsupported_ops).
    /// Reported at program load. Mirrors the kernel's
    /// "attach to unsupported member <member> of struct <ops_struct>".
    UnsupportedStructOpsMember {
        ops_struct: String,
        member: String,
    },
    /// Non-GPL-compatible BPF program attaching to a GPL-only struct_ops
    /// (e.g. `tcp_congestion_ops`). Mirrors the kernel's struct_ops
    /// registration which sets `BPF_PROG_GPL_ONLY` for these ops_structs;
    /// the loader rejects with EINVAL when the program license isn't
    /// GPL-compatible per `license_is_gpl_compatible`.
    StructOpsRequiresGpl {
        ops_struct: String,
        license: String,
    },
    /// libbpf rejects a struct_ops program assigned to multiple
    /// member slots ("invalid reuse of prog <name>"). The kernel
    /// verifier never runs in this case — the load fails earlier
    /// in libbpf. Pattern observed in `bad_struct_ops` (prog
    /// `test_1` wired to both `bpf_testmod_ops::test_1` and
    /// `bpf_testmod_ops2::test_1`).
    StructOpsProgReuse {
        prog: String,
    },
    GlobalFuncMalformed {
        pc: usize,
        func: String,
        reason: String,
    },
    GlobalFuncBadCallerArg {
        pc: usize,
        func: String,
        arg_index: usize,
    },
    /// CallRel into a global subprog whose static call-graph reaches a
    /// MIGHT_SLEEP helper/kfunc, from inside an irq- or preempt-disabled
    /// region. Kernel: "global functions that may sleep are not allowed
    /// in non-sleepable context".
    /// Kernel verifier.c L10538: a global subprog call site is inside a
    /// held bpf_spin_lock region. The kernel rejects unconditionally
    /// (path-independent) because global subprogs are verified separately
    /// and may execute arbitrary helpers / kfuncs that are illegal under
    /// lock. Static subprogs are inlined and exempt.
    GlobalFuncCallUnderLock {
        pc: usize,
        func: String,
    },
    GlobalFuncMaySleepInNonSleepable {
        pc: usize,
        func: String,
    },
    LsmHookDisabled {
        hook: String,
    },
    /// Kfunc proto carries a `prog_type_allowlist` and the
    /// program's `ProgramKind` is not in it. Mirrors the kernel
    /// verifier's per-kfunc `KF_PROG_TYPE_*` check (e.g. cgroup /
    /// cpumask / task families are gated to syscall / tracepoint /
    /// perf_event and reject from raw_tp).
    KfuncNotAllowedForProgram {
        pc: usize,
        btf_id: u32,
        kind: ProgramKind,
    },
    /// kfunc rejected because the calling subprog is wired
    /// into a struct_ops member that's not in the kfunc's allowed
    /// (ops_struct, member) set. E.g. `scx_bpf_select_cpu_dfl` is
    /// callable only from `sched_ext_ops.select_cpu`.
    KfuncNotAllowedForOpsMember {
        pc: usize,
        btf_id: u32,
        ops_struct: String,
        member: String,
    },
    PointerLeakage {
        pc: usize,
        offset: i64,
    },
    MapKeyOutOfBounds {
        pc: usize,
        key_min: i64,
        key_max: i64,
        max_entries: u32,
    },
    InvalidHelperId {
        pc: usize,
        helper: u32,
    },
    /// A valid-shape construct the verifier recognizes but has not implemented
    /// transfer semantics for yet (e.g. kfunc calls, BPF_PSEUDO_FUNC / BTF_ID
    /// LD_IMM64 subtypes added by kernels newer than 5.15).
    UnsupportedModernFeature {
        pc: usize,
        feature: &'static str,
    },
    /// Load-time rejection of an `__exception_cb(name)` annotation.
    /// Carries the kernel-style diagnostic verbatim — duplicates,
    /// non-scalar return type, wrong arity, etc. Reported per main
    /// subprog before analysis runs.
    ExceptionCallbackInvalid {
        reason: String,
    },
}

impl VerificationError {
    pub fn description(&self) -> String {
        match self {
            VerificationError::StackOutOfBounds { pc, off, size } => {
                format!(
                    "Stack out of bounds at pc {}: offset {}, size {}",
                    pc, off, size
                )
            }
            VerificationError::PointerOutOfBounds { pc } => {
                format!("Pointer out of bounds at pc {}", pc)
            }
            VerificationError::UninitializedStackRead { pc, offset } => {
                format!(
                    "Reading uninitialized stack slot at pc {}: offset {}",
                    pc, offset
                )
            }
            VerificationError::UnsafePacketLoad { pc, off, size } => {
                format!(
                    "Unsafe packet load at pc {}: offset {}, size {:?}",
                    pc, off, size
                )
            }
            VerificationError::UnsafePacketStore { pc, off, size } => {
                format!(
                    "Unsafe packet store at pc {}: offset {}, size {:?}",
                    pc, off, size
                )
            }
            VerificationError::IllegalPacketStore { pc, off, size } => {
                format!(
                    "Illegal packet store at pc {}: offset {}, size {:?}",
                    pc, off, size
                )
            }
            VerificationError::UnsafeMapLoad {
                pc,
                off,
                size,
                limit,
            } => {
                format!(
                    "Unsafe map load at pc {}: offset {}, size {:?}, limit {}",
                    pc, off, size, limit
                )
            }
            VerificationError::UnsafeMapStore {
                pc,
                off,
                size,
                limit,
            } => {
                format!(
                    "Unsafe map store at pc {}: offset {}, size {:?}, limit {}",
                    pc, off, size, limit
                )
            }
            VerificationError::UnsafeMapAccess { pc, map_idx, size } => {
                format!(
                    "Unsafe map store at pc {}: map index {}, size {:?}",
                    pc, map_idx, size
                )
            }
            VerificationError::UnsafeGenericLoad {
                pc,
                base,
                off,
                base_type,
            } => {
                format!(
                    "Unsafe generic load at pc {}: base {:?}+{} (type: {:?})",
                    pc, base, off, base_type
                )
            }
            VerificationError::UnsafeCtxAccess { pc, off, size } => {
                format!(
                    "Unsafe ctx access at pc {}: offset {}, size {:?}",
                    pc, off, size
                )
            }
            VerificationError::UnsafeGenericStore {
                pc,
                base,
                off,
                base_type,
            } => {
                format!(
                    "Unsafe generic store at pc {}: base {:?}+{} (type: {:?})",
                    pc, base, off, base_type
                )
            }
            VerificationError::DbmInconsistent { pc } => {
                format!("DBM inconsistent at pc {}", pc)
            }
            VerificationError::ComplexityLimitExceeded { limit } => {
                format!("Complexity limit of {} exceeded", limit)
            }
            VerificationError::InfiniteLoopDetected { pc } => {
                format!("infinite loop detected at insn {}", pc)
            }
            VerificationError::CfgError(msg) => {
                format!("CFG error: {}", msg)
            }
            VerificationError::DivideByZero { pc } => {
                format!("Potential divide by zero at pc {}", pc)
            }
            VerificationError::UnsafeSocketAccess { pc, off, size } => {
                format!(
                    "Unsafe socket access at pc {}: offset {}, size {:?}",
                    pc, off, size
                )
            }
            VerificationError::UnsafeMemoryRegionLoad { pc, base, off } => {
                format!(
                    "Unsafe memory region load at pc {}: base {:?}, offset {}",
                    pc, base, off
                )
            }
            VerificationError::InvalidArgType { pc, reg } => {
                format!(
                    "Invalid argument type at pc {}: register: {}",
                    pc,
                    reg.name()
                )
            }
            VerificationError::InvalidPointerArithmetic { pc } => {
                format!("Invalid pointer arithmetic at pc {}", pc)
            }
            VerificationError::InvalidStackRead { pc, offset } => {
                format!("Invalid stack read at pc {} offset {}", pc, offset)
            }
            VerificationError::RegisterNotReadable { pc, reg } => {
                format!("pc {}: {:?} !read_ok", pc, reg)
            }
            VerificationError::RegisterNotWritable { pc, reg } => {
                format!("pc {}: {:?} !write_ok", pc, reg)
            }
            VerificationError::InvalidBPFLoadImmInsn { pc } => {
                format!("Invalid BPF_LD_IMM instruction at pc {}", pc)
            }
            VerificationError::MapNotFound { pc, map_idx } => {
                format!("Map with ID {} not found at pc {}", map_idx, pc)
            }
            VerificationError::BackEdge { pc, target } => {
                format!("Attempting to jump back to {} at pc {}", target, pc)
            }
            VerificationError::MaxCallDepthExceeded { pc } => {
                format!("Max call depth exceeded at pc {}", pc)
            }
            VerificationError::MisalignedAccess { pc, off } => {
                format!("Misaligned offset with offset {} at pc {}", off, pc)
            }
            VerificationError::InvalidReturnCode { pc } => {
                format!("Invalid return code at pc {}", pc)
            }
            VerificationError::MisalignedPacketAccess { pc, off, size } => {
                format!(
                    "Misaligned packet access at pc {}: offset {}, size {:?}",
                    pc, off, size
                )
            }
            VerificationError::InvalidRegisterTypeState { pc } => {
                format!("Invalid register type state at pc {}", pc)
            }
            VerificationError::MapStoreForbidden { pc, map_idx } => {
                format!("Attemp to write to read-only map {} at pc {}", map_idx, pc)
            }
            VerificationError::MapLoadForbidden { pc, map_idx } => {
                format!(
                    "Attemp to read from write-only map {} at pc {}",
                    map_idx, pc
                )
            }
            VerificationError::RegisterTypeConflict { pc, reg, old, new } => {
                format!(
                    "Register {} type conflict at pc {}: old: {:?}, new: {:?}",
                    reg.name(),
                    pc,
                    old,
                    new
                )
            }
            VerificationError::UnreleasedReference => "Unreleased reference in program".to_string(),
            VerificationError::UnreleasedIterator => {
                "Unreleased open-coded iterator in program".to_string()
            }
            VerificationError::UnreleasedDynptr => "Unreleased dynptr in program".to_string(),
            VerificationError::DynptrOverwrite { pc, off } => format!(
                "Cannot overwrite referenced dynptr at pc {} (stack off {})",
                pc, off
            ),
            VerificationError::IteratorOverwrite { pc, off } => format!(
                "Cannot overwrite open-coded iterator slot at pc {} (stack off {})",
                pc, off
            ),
            VerificationError::IrqFlagOverwrite { pc, off } => format!(
                "Cannot overwrite irq flag stack slot at pc {} (stack off {})",
                pc, off
            ),
            VerificationError::IrqState { pc, reason } => {
                format!("IRQ state error at pc {}: {}", pc, reason)
            }
            VerificationError::KptrAccessSizeMustBeDW { pc, off, size } => format!(
                "kptr access size must be BPF_DW at pc {} (off {}, size {})",
                pc, off, size
            ),
            VerificationError::KptrAccessMisaligned { pc, off, expected } => format!(
                "kptr access misaligned expected={} off={} at pc {}",
                expected, off, pc
            ),
            VerificationError::KptrAccessVariableOffset { pc, map_idx } => format!(
                "kptr access cannot have variable offset (map {}) at pc {}",
                map_idx, pc
            ),
            VerificationError::KptrStoreToReferenced { pc, off } => format!(
                "store to referenced kptr disallowed at pc {} (off {})",
                pc, off
            ),
            VerificationError::UptrStoreDisallowed { pc, off } => {
                format!("store to uptr disallowed at pc {} (off {})", pc, off)
            }
            VerificationError::UnreleasedLock => "Unreleased lock in program".to_string(),
            VerificationError::InvalidBtfType => "Invalid BTF type".to_string(),
            VerificationError::LockAlreadyHeld { pc } => {
                format!("Lock already held at pc {}, cannot acquire again", pc)
            }
            VerificationError::LockNotHeld { pc } => {
                format!("Lock not held at pc {}, cannot release", pc)
            }
            VerificationError::RcuReadNotHeld { pc } => {
                format!("RCU read-side section not held at pc {}, cannot unlock", pc)
            }
            VerificationError::NotInRcuReadSection { pc, helper } => {
                format!(
                    "Helper {} at pc {} requires an RCU read-side critical section",
                    helper, pc
                )
            }
            VerificationError::UnreleasedRcuRead => {
                "Unreleased RCU read-side section in program".to_string()
            }
            VerificationError::SleepableInRcuReadSection { pc, helper } => {
                format!(
                    "Sleepable helper/kfunc {} invoked inside bpf_rcu_read_lock region at pc {}",
                    helper, pc
                )
            }
            VerificationError::SleepableInPreemptDisabled { pc, helper } => {
                format!(
                    "Sleepable helper/kfunc {} in preempt-disabled region at pc {}",
                    helper, pc
                )
            }
            VerificationError::PreemptNotDisabled { pc } => {
                format!("Unmatched bpf_preempt_enable at pc {}", pc)
            }
            VerificationError::ExitInPreemptDisabled => {
                "BPF_EXIT in main prog inside bpf_preempt_disable-ed region".to_string()
            }
            VerificationError::TailCallInPreemptDisabled { pc } => {
                format!(
                    "tail_call cannot be used inside bpf_preempt_disable-ed region at pc {}",
                    pc
                )
            }
            VerificationError::NotInSpinLockSection { pc, helper } => {
                format!(
                    "Helper/kfunc {} at pc {} requires an active spin_lock",
                    helper, pc
                )
            }
            VerificationError::LoadAbsUnderLock { pc } => {
                format!("ld_abs with an active lock at pc {}", pc)
            }
            VerificationError::RelocationInfoMissing { pc } => {
                format!("Relocation info missing at pc {}", pc)
            }
            VerificationError::SubprogError { e } => {
                format!("Subprogram error: {}", e)
            }
            VerificationError::CannotReturnStackPointer { pc } => {
                format!("Cannot return stack pointer in R0 at pc {}", pc)
            }
            VerificationError::SpillToCaller { pc } => {
                format!("Spill to caller at pc {}", pc)
            }
            VerificationError::HelperNotAllowedForProgram { pc, helper, kind } => {
                format!(
                    "Helper {} not allowed for program {:?} at pc {}",
                    helper, kind, pc
                )
            }
            VerificationError::MapProgIncompat {
                map_name,
                field,
                kind,
            } => {
                format!(
                    "tracing/socket-filter prog {:?} cannot use map '{}' with {} field",
                    kind, map_name, field
                )
            }
            VerificationError::LsmHookDisabled { hook } => {
                format!("LSM attach target points to disabled hook '{}'", hook)
            }
            VerificationError::NoreturnAttachTarget { target } => {
                format!(
                    "Attaching fexit/fmod_ret to __noreturn functions is rejected: '{}'",
                    target
                )
            }
            VerificationError::TracingAttachDenied { target } => {
                format!(
                    "Tracing program cannot attach to denied kernel function '{}'",
                    target
                )
            }
            VerificationError::UnsupportedStructOpsMember { ops_struct, member } => {
                format!(
                    "attach to unsupported member {} of struct {}",
                    member, ops_struct
                )
            }
            VerificationError::StructOpsRequiresGpl {
                ops_struct,
                license,
            } => {
                format!(
                    "struct_ops {} requires GPL-compatible license, got '{}'",
                    ops_struct, license
                )
            }
            VerificationError::StructOpsProgReuse { prog } => {
                format!("invalid reuse of prog {}", prog)
            }
            VerificationError::GlobalFuncMalformed { pc, func, reason } => {
                format!("global function '{}' at pc {} {}", func, pc, reason)
            }
            VerificationError::GlobalFuncBadCallerArg {
                pc,
                func,
                arg_index,
            } => {
                format!(
                    "Caller passes invalid args into func '{}' (arg #{}) at pc {}",
                    func,
                    arg_index + 1,
                    pc
                )
            }
            VerificationError::GlobalFuncCallUnderLock { pc, func } => {
                format!(
                    "global function calls are not allowed while holding a lock: call to '{}' at pc {}",
                    func, pc
                )
            }
            VerificationError::GlobalFuncMaySleepInNonSleepable { pc, func } => {
                format!(
                    "global functions that may sleep are not allowed in non-sleepable context: call to '{}' at pc {}",
                    func, pc
                )
            }
            VerificationError::KfuncNotAllowedForProgram { pc, btf_id, kind } => {
                format!(
                    "Kfunc btf_id {} not allowed for program {:?} at pc {}",
                    btf_id, kind, pc
                )
            }
            VerificationError::KfuncNotAllowedForOpsMember {
                pc,
                btf_id,
                ops_struct,
                member,
            } => {
                format!(
                    "Kfunc btf_id {} not allowed in {}.{} at pc {}",
                    btf_id, ops_struct, member, pc
                )
            }
            VerificationError::UnsafeMemoryStore {
                pc,
                base,
                off,
                size,
            } => {
                format!(
                    "Unsafe memory store at pc {}: base {:?}, offset {}, size {}",
                    pc, base, off, size
                )
            }
            VerificationError::UnsafeMemoryLoad {
                pc,
                base,
                off,
                size,
            } => {
                format!(
                    "Unsafe memory load at pc {}: base {:?}, offset {}, size {}",
                    pc, base, off, size
                )
            }
            VerificationError::PointerLeakage { pc, offset } => {
                format!(
                    "Pointer leakage at pc {}: stack slot {} contains pointer that cannot be exposed to map",
                    pc, offset
                )
            }
            VerificationError::MapKeyOutOfBounds {
                pc,
                key_min,
                key_max,
                max_entries,
            } => {
                format!(
                    "Map key out of bounds at pc {}: key range [{}, {}], max_entries={}",
                    pc, key_min, key_max, max_entries
                )
            }
            VerificationError::InvalidHelperId { pc, helper } => {
                format!(
                    "Invalid helper ID {} at pc {}: exceeds maximum known helper ID",
                    helper, pc
                )
            }
            VerificationError::UnsupportedModernFeature { pc, feature } => {
                format!("Unsupported modern BPF feature at pc {}: {}", pc, feature)
            }
            VerificationError::ExceptionCallbackInvalid { reason } => reason.clone(),
        }
    }
}
