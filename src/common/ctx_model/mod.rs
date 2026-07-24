// Data-driven BPF context field definitions and access validation.
//
// The layout of BPF context structures (sk_buff, xdp_md, etc.) lives in
// `tables.rs` as static data; this module holds the types and the
// read/write validation logic over those tables.

use crate::{
    analysis::machine::env::VerifierEnv,
    ast::{AttachKind, ContextKind, MemSize, ProgramKind},
};

mod tables;
pub use tables::*;

// ===========================================================================
// Core Types
// ===========================================================================

/// What kind of value a ctx field holds (for type inference after loads).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtxFieldKind {
    /// Plain scalar (int, flags, etc.). No pointer semantics.
    Scalar,

    /// A pointer into some memory region.
    SockCommon,

    /// Trusted, non-null `struct bpf_sock *` ctx field. Maps to
    /// `RegType::PtrToSocket { ref_id: None }`. Used for ctx fields the
    /// kernel guarantees non-null at program entry (e.g. `bpf_sockopt.sk`,
    /// where `cgroup_sockopt_is_valid_access` returns `PTR_TO_SOCKET`).
    /// Distinct from `SockCommon`, which yields the nullable `*OrNull`
    /// form because most other contexts (sk_buff, sk_lookup, …) deliver
    /// the sk pointer in a state that still requires a null-check.
    Socket,

    /// Nullable `struct bpf_sock *` ctx field. Maps to
    /// `RegType::PtrToSocketOrNull { ref_id: None }`. Used for sk_lookup
    /// ctx->sk where kernel returns PTR_TO_SOCKET_OR_NULL (the field
    /// reflects the verdict's selected sk; null until bpf_sk_assign).
    /// JEQ-refinement against a sk1 from `bpf_map_lookup_elem` on a
    /// SOCKMAP (also PtrToSocket flavor) promotes the nullable side.
    SocketOrNull,

    /// Pointer to the start of the packet data.
    PacketStart,

    /// Pointer to the end of the packet data.
    PacketEnd,

    /// Pointer to packet metadata
    PacketMeta,

    /// Bounded data buffer (PTR_TO_BUF equivalent). Used for iter ctx
    /// `void *` fields like `bpf_iter__bpf_map_elem.{key,value}` —
    /// kernel exposes them as PTR_TO_BUF with size from the iter's
    /// target map. We don't have map context generically, so use a
    /// generous fixed bound.
    AllocMem {
        mem_size: u64,
    },

    /// Trusted pointer to a kernel struct (PTR_TO_BTF_ID equivalent).
    ///
    /// `trusted` mirrors kernel `prog_args_trusted()` (btf.c v6.15
    /// L6422): entry args are TRUSTED for tp_btf / raw_tp / iter /
    /// LSM / struct_ops, but plain `PTR_TO_BTF_ID` (untrusted) for
    /// fentry / fexit / fmod_ret. ARG_PTR_TO_MEM helpers
    /// (`bpf_strncmp`, `bpf_probe_read_kernel`, …) reject untrusted
    /// PTR_TO_BTF_ID via the `mem_types` table (verifier.c L9019).
    /// Closes `task_kfunc_failure::task_access_comm4` (fentry rejects
    /// `bpf_strncmp(task->comm, 16, …)` with "R1 type=ptr_ expected").
    /// Default is `true` (legacy behavior); fentry/fexit/fmod_ret
    /// entry-arg paths set it `false`.
    TrustedPtr {
        type_name: &'static str,
        nullable: bool,
        /// True iff the kernel marks this ctx-arg load as
        /// `PTR_TO_BTF_ID | PTR_TRUSTED`. False for fentry/fexit/
        /// fmod_ret entry args (the kernel "legacy ptr_to_btf_id"
        /// case).
        trusted: bool,
        /// BTF TYPE_TAG flags from the attach-target arg (USER /
        /// PERCPU). Default empty for static ctx-field tables; the
        /// fentry/LSM/tp_btf lax fallback populates this from
        /// `attach_rules::tracing_attach_arg_tag_flags(attach_subtype, arg_idx)`.
        /// Propagated to `RegType::PtrToBtfId.flags` by transfer/types.rs;
        /// rejected at deref by access.rs.
        tag_flags: crate::analysis::machine::reg_types::PtrFlags,
    },

    /// Bounded scalar field: a normal scalar with a known `[lo, hi]`
    /// integer range applied at load time. Used for LSM int-hook
    /// trailing `int ret` args (kernel constrains to `[-MAX_ERRNO, 0]`
    /// at attach). Materializes as `RegType::ScalarValue` with the
    /// destination register's interval domain bounded.
    BoundedScalar {
        lo: i64,
        hi: i64,
    },
    /// struct_ops `task_struct *task__ref` ctx-array slot — the
    /// `EntryArg::TrustedRefcountedTask` companion. Materializes as
    /// `RegType::PtrToTask { ref_id: Some(ref_id) }` so the matching
    /// `bpf_task_release(task)` consumes the entry-acquired ref.
    RefcountedTask {
        ref_id: u32,
    },
}

/// A field in a BPF context struct.
#[derive(Clone, Copy, Debug)]
pub struct CtxField {
    /// Byte offset from context base
    pub offset: i16,
    /// Required access size
    pub size: MemSize,
    /// What kind of value this field holds
    pub kind: CtxFieldKind,
    /// Whether this field can be written by BPF programs
    pub writable: bool,
    /// Whether this field can be read by BPF programs
    pub readable: bool,
    /// Allow subfield r/w
    pub narrow_access: bool,
}

/// A contiguous scratch region in a context struct where any
/// aligned access within bounds is permitted (e.g., __sk_buff.cb).
pub struct CtxRegion {
    pub start: i16,
    pub end: i16,
    pub readable: bool,
    pub writable: bool,
}

/// Result of validating a context access.
#[derive(Clone, Copy, Debug)]
pub struct CtxAccessInfo {
    /// What kind of value this field holds
    pub kind: CtxFieldKind,
    /// Whether this field can be written
    pub writable: bool,
    /// Whether this field can be read
    pub readable: bool,
}

// ===========================================================================
// Field Tables
// ===========================================================================

/// struct __sk_buff (TC/classifier context)
///
/// Reference: linux/include/uapi/linux/bpf.h
///
/// Note: The __sk_buff struct exposed to BPF is a "view" that the kernel
/// rewrites accesses for. Field offsets here match the BPF-visible layout.
fn lookup_field(fields: &[CtxField], off: i16, size: i64) -> Option<CtxAccessInfo> {
    let access_end = off + size as i16;

    // Check natural alignment
    let aligned = off % size as i16 == 0;
    if !aligned {
        return None;
    }

    fields
        .iter()
        .find(|f| {
            if f.narrow_access {
                // Allow aligned sub-field access within bounds
                let field_end = f.offset + f.size.bytes() as i16;
                off >= f.offset && access_end <= field_end
            } else {
                // Require exact offset and size match
                f.offset == off && f.size.bytes() == size as usize
            }
        })
        .map(|f| CtxAccessInfo {
            kind: f.kind,
            readable: f.readable,
            writable: f.writable,
        })
}

fn lookup_region(ctx_kind: ContextKind, off: i16, size: i64) -> Option<CtxAccessInfo> {
    let access_end = off + size as i16;

    // Must be a power-of-2 size (1, 2, 4, 8)
    if size <= 0 || (size & (size - 1) != 0) || size > 8 {
        return None;
    }

    // Check natural alignment
    if off % size as i16 != 0 {
        return None;
    }

    get_regions(ctx_kind)
        .iter()
        .find(|r| off >= r.start && access_end <= r.end)
        .map(|r| CtxAccessInfo {
            kind: CtxFieldKind::Scalar,
            readable: r.readable,
            writable: r.writable,
        })
}

/// Get the field table for a given context kind.
fn get_field_tables(
    ctx_kind: ContextKind,
    prog_kind: ProgramKind,
    attach_subtype: Option<&str>,
) -> Option<(&'static [CtxField], &'static [CtxField])> {
    match ctx_kind {
        ContextKind::SkBuff => {
            let extended: &[CtxField] = match prog_kind {
                ProgramKind::CgroupSkb | ProgramKind::SchedCls | ProgramKind::SchedAct => {
                    SK_BUFF_EXTENDED_FIELDS
                }
                ProgramKind::FlowDissector => FLOW_DISSECTOR_EXTENDED_FIELDS,
                _ => &[],
            };
            Some((SK_BUFF_FIELDS, extended))
        }
        ContextKind::XdpMd => {
            // egress_ifindex is gated on BPF_XDP_DEVMAP attach type
            // (SEC("xdp/devmap") / SEC("xdp.frags/devmap")).
            let extended: &[CtxField] = if attach_subtype == Some("devmap") {
                XDP_MD_DEVMAP_FIELDS
            } else {
                &[]
            };
            Some((XDP_MD_FIELDS, extended))
        }
        ContextKind::BpfSockAddr => Some((SOCK_ADDR_FIELDS, &[])),
        ContextKind::BpfSockopt => Some((BPF_SOCKOPT_FIELDS, &[])),
        ContextKind::SkLookup => Some((SK_LOOKUP_FIELDS, &[])),
        ContextKind::SkReuseport => Some((SK_REUSEPORT_FIELDS, &[])),
        ContextKind::SockOps => Some((SOCK_OPS_FIELDS, &[])),
        ContextKind::BpfSock => Some((BPF_SOCK_FIELDS, &[])),
        ContextKind::SkMsgMd => Some((SK_MSG_MD_FIELDS, &[])),
        ContextKind::PtRegs => Some((PT_REGS_FIELDS, &[])),
        ContextKind::IterTask => Some((TRACE_ITER_TASK_FIELDS, &[])),
        _ => None,
    }
}

fn get_regions(ctx_kind: ContextKind) -> &'static [CtxRegion] {
    match ctx_kind {
        ContextKind::SkBuff => &[CtxRegion {
            start: SK_BUFF_CB_START,
            end: SK_BUFF_CB_END,
            readable: true,
            writable: true,
        }],
        ContextKind::BpfSockAddr => &[
            CtxRegion {
                start: SOCK_ADDR_USER_IP6_START,
                end: SOCK_ADDR_USER_IP6_END,
                readable: true,
                writable: true,
            },
            CtxRegion {
                start: SOCK_ADDR_MSG_SRC_IP6_START,
                end: SOCK_ADDR_MSG_SRC_IP6_END,
                readable: true,
                writable: true,
            },
        ],
        _ => &[],
    }
}

/// Apply program-type-specific access overrides.
/// Called after base field lookup to adjust readable/writable based on program type.
fn apply_prog_type_overrides(prog_kind: ProgramKind, off: i16, info: &mut CtxAccessInfo) {
    let ctx_kind = prog_kind.context_kind();

    if ctx_kind == ContextKind::SkBuff {
        match off {
            // mark (offset 8)
            8 => match prog_kind {
                ProgramKind::SkSkb => {
                    info.readable = false;
                    info.writable = false;
                }
                _ => {
                    info.readable = true;
                    info.writable = true;
                }
            },
            // priority (offset 32)
            // Writable for CgroupSkb, SchedCls, SchedAct
            32 => match prog_kind {
                ProgramKind::CgroupSkb | ProgramKind::SchedCls | ProgramKind::SchedAct => {
                    info.writable = true;
                }
                _ => {}
            },
            // tc_classid (offset 72)
            // - TC ingress: write-only
            // - TC egress: read-write
            // - SK_SKB: not accessible
            72 => {
                match prog_kind {
                    ProgramKind::SkSkb => {
                        info.readable = false;
                        info.writable = false;
                    }
                    ProgramKind::SchedCls | ProgramKind::SchedAct => {
                        // TODO: ideally check attach type for ingress vs egress
                        // Conservative: mark as write-only
                        info.readable = false;
                    }
                    _ => {
                        info.readable = false;
                        info.writable = false;
                    }
                }
            }
            // data and data_end
            76..=80 => {
                if !matches!(
                    prog_kind,
                    ProgramKind::SchedCls
                        | ProgramKind::SchedAct
                        | ProgramKind::SkSkb
                        | ProgramKind::LwtIn
                        | ProgramKind::LwtOut
                        | ProgramKind::LwtXmit
                        | ProgramKind::CgroupSkb
                        | ProgramKind::FlowDissector
                ) {
                    info.readable = false;
                }
            }
            // family, remote_ip4, local_ip4, remote_ip6, local_ip6, remote_port, local_port
            // Only readable for cgroup_skb, sock_ops, sk_skb programs
            88 | 92 | 96 | 100..=128 | 132 | 136 => {
                if !matches!(
                    prog_kind,
                    ProgramKind::CgroupSkb | ProgramKind::SockOps | ProgramKind::SkSkb
                ) {
                    info.readable = false;
                }
            }
            // data_meta (offset 140)
            140 => {
                if matches!(prog_kind, ProgramKind::CgroupSkb | ProgramKind::SockOps) {
                    info.readable = false;
                }
            }
            // tstamp (offset 152)
            // Readable for extended program types (via extended table)
            // Writable only for CgroupSkb, SchedCls, SchedAct
            152 => match prog_kind {
                ProgramKind::CgroupSkb | ProgramKind::SchedCls | ProgramKind::SchedAct => {
                    info.writable = true;
                }
                _ => {}
            },
            // wire_len (offset 160), gso_segs (offset 164), gso_size (offset 176)
            // Read-only for all extended program types, no overrides needed
            _ => {}
        }
    }
}

// ===========================================================================
/// Mirrors kernel `prog_args_trusted()` (btf.c v6.15 L6422). Returns
/// true iff ctx-arg loads in this attach context get
/// `PTR_TO_BTF_ID | PTR_TRUSTED`. False for the "legacy ptr_to_btf_id"
/// case (plain `PTR_TO_BTF_ID`) — fentry / fexit / fmod_ret in
/// particular. Used by the entry-args ctx access path to gate the
/// downstream `PtrFlags::TRUSTED` flag, which in turn governs whether
/// the pointer satisfies ARG_PTR_TO_MEM helpers like `bpf_strncmp`
/// (kernel `mem_types` requires TRUSTED, verifier.c L9019).
fn entry_arg_trusted_for_attach(
    prog_kind: crate::ast::ProgramKind,
    attach_flavor: Option<&str>,
) -> bool {
    use crate::ast::ProgramKind;
    match prog_kind {
        // BPF_PROG_TYPE_TRACING: only RAW_TP and ITER are trusted.
        // fentry/fexit/fmod_ret are PTR_TO_BTF_ID without PTR_TRUSTED.
        ProgramKind::Tracing => matches!(
            attach_flavor,
            Some("tp_btf") | Some("raw_tp") | Some("raw_tp.w") | Some("iter") | Some("iter.s")
        ),
        // BPF_PROG_TYPE_LSM: kernel checks `bpf_lsm_is_trusted`; almost
        // all hooks are trusted. Default true for the LSM-corpus paths
        // we exercise; tighten if a counterexample surfaces.
        ProgramKind::Lsm => true,
        // BPF_PROG_TYPE_STRUCT_OPS: always trusted.
        ProgramKind::StructOps => true,
        // Other kinds reach this helper via the same fallback paths;
        // their classic ctx-field tables already establish trust at
        // the per-field level (network ctx, etc.).
        _ => true,
    }
}


// ===========================================================================
// Public API
// ===========================================================================

/// Validate a context access and return field info if valid.
///
/// Returns:
/// - `Some(info)` if the access is valid, with field kind and writability
/// - `None` if the access is invalid (wrong offset, wrong size, or unknown context)
pub fn validate_ctx_access(env: &VerifierEnv, off: i16, size: i64) -> Option<CtxAccessInfo> {
    let prog_kind = env.ctx.prog_kind;

    // SEC("syscall") — BPF_PROG_TYPE_SYSCALL accepts a user-defined ctx
    // struct via BPF_PROG_TEST_RUN's `ctx_in` (size = `ctx_size_in`).
    // Kernel `bpf_syscall_prog_is_valid_access` admits any aligned r/w
    // within the user-supplied bound; the layout isn't statically
    // known. Admit any non-negative aligned access up to a generous
    // bound; result is Scalar. R1 stays as PtrToCtx so global subprog
    // `__arg_ctx` validation (verifier_global_subprogs::arg_tag_ctx_syscall)
    // still works — the type identity is preserved.
    if prog_kind == ProgramKind::Syscall
        && off >= 0
        && size > 0
        && size <= 8
        && (size & (size - 1)) == 0
        && off % size as i16 == 0
        && (off as i64 + size) <= 4096
    {
        return Some(CtxAccessInfo {
            kind: CtxFieldKind::Scalar,
            readable: true,
            writable: true,
        });
    }

    // raw_tracepoint ctx is `struct bpf_raw_tracepoint_args { __u64
    // args[MAX_BPF_FUNC_ARGS]; }` (kernel `include/linux/bpf.h`).
    // `raw_tp_prog_is_valid_access` (bpf_trace.c) defers to
    // `bpf_tracing_ctx_access` (bpf.h), which validates bounds /
    // alignment / read-only and leaves `info->reg_type` unset — so the
    // kernel types every load as SCALAR_VALUE, regardless of what
    // `BPF_PROG()` wrappers cast the args to. Without this arm the
    // entry_args / lax-TrustedPtr fallbacks further down can over-type
    // an 8-byte raw_tp ctx slot as PtrToBtfId{"unknown"}, and a
    // subsequent shift/and on the value rejects as "Invalid pointer
    // arithmetic" (inspektor-gadget seccomp `ig_seccomp_e`: PC 30 loads
    // `args[1]`, PC 42 does `r1 <<= 32` for u32 zero-extension).
    // raw_tp.w differs only at off=0 (PTR_TO_TP_BUFFER write target);
    // keep that on the existing path until we model PtrToTpBuffer.
    if prog_kind == ProgramKind::RawTracepoint
        && off >= 0
        && size > 0
        && size <= 8
        && (size & (size - 1)) == 0
        && off % size as i16 == 0
        // 8 * MAX_BPF_FUNC_ARGS = 8 * 12 = 96; kernel bound from
        // `bpf_tracing_ctx_access` (`off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS`).
        && (off as i64 + size) <= 96
    {
        return Some(CtxAccessInfo {
            kind: CtxFieldKind::Scalar,
            readable: true,
            writable: false,
        });
    }

    // struct_ops subprogs receive their args via the BPF_PROG
    // wrapper's ctx-array idiom — clang emits each arg access as
    // `r_n = *(u64 *)(r1 + 8*i)` followed by an explicit cast to the
    // declared type. The verifier sees a PtrToCtx load whose result must
    // be typed as the i-th declared arg. We model this from the
    // `entry_args` vector cached on ExecContext (populated by the
    // runner from the struct_ops bindings + BTF resolver).
    //
    // Only 8-byte aligned 8-byte loads at offsets 0/8/16/... are
    // recognized; this matches the codegen of the BPF_PROG macro and
    // avoids accidentally typing partial-byte reads that would have to
    // come from a different idiom.
    // extended to fentry/fexit/tp_btf/lsm/tracepoint.
    // The BPF_PROG() macro generates the same ctx-array idiom in all
    // these prog types; the runner now resolves entry_args from the
    // function's BTF FUNC_PROTO for non-struct_ops kinds via
    // `btf.resolve_func_args(func_name)`.
    // Iter / sk_reuseport ctx loads: R1 holds a typed ctx pointer
    // directly (no BPF_PROG wrapper). `*(u64 *)(r1 + off)` is a field
    // load on the ctx struct, not the BPF_PROG ctx-array idiom. Look
    // up `(ctx_struct, off)` in BTF and type the load via the
    // `trusted_field_load` allowlist.
    // SkReuseport now has its own static field table (`SK_REUSEPORT_FIELDS`)
    // — fall through to the standard ctx-table lookup so the data /
    // data_end / sk / migrating_sk fields produce typed pointers
    // (PtrToPacket, PtrToSocket, PtrToSockCommonOrNull) instead of the
    // BTF-driven Scalar/AllocMem fallback that this direct-typed path
    // returns.
    // Direct-typed ctx: programs whose ctx pointer is named (carries
    // a real BTF struct name in arg0) and supports field access by
    // offset. Covers:
    //  - iter programs (`bpf_iter__<X>` ctx, BPF_PROG-wrapped)
    //  - raw_tracepoint with `struct pt_regs *ctx` (kprobe-style direct
    //    pt_regs access). Without this, raw_tracepoint pt_regs.ax loads
    //    fall into the lax TrustedPtr fallback and the program FRs on
    //    arithmetic over the bogus pointer (loop1::nested_loops).
    let is_direct_typed_ctx = (prog_kind == ProgramKind::Tracing
        && matches!(env.ctx.attach_flavor.as_deref(), Some("iter")))
        || matches!(
            prog_kind,
            ProgramKind::RawTracepoint | ProgramKind::RawTracepointWritable
        );
    // Direct typed ctx loads: 8-byte pointer fields and 1/2/4/8-byte
    // scalar fields. The size-8/off%8 path resolves pointer-typed
    // fields via BTF (allowlisted); the size-1/2/4/8 path falls
    // through to Scalar so per-iter-subtype ctx structs that we
    // don't model in detail (bpf_iter__tcp::uid, bpf_iter__task_file
    // ::fd, etc.) accept the loads the kernel admits.
    if is_direct_typed_ctx && size > 0 && off >= 0 && (size & (size - 1)) == 0 && size <= 8
        && off % size as i16 == 0
    {
        if let Some(args) = env.ctx.entry_args.as_ref()
            && let Some(arg0) = args.first()
        {
            use crate::analysis::machine::context::{
                EntryArg, intern_btf_type_name_strict,
            };
            use crate::analysis::transfer::field_tables::trusted_field_load;
            use crate::parsing::btf::BtfFieldKind;
            if let EntryArg::TrustedPtrBtfId { type_name, .. } = arg0 {
                if size == 8
                    && let Some(struct_id) = env.ctx.btf.find_struct_by_name(type_name)
                    && let Some(info) =
                        env.ctx.btf.field_at_offset(struct_id, off as u32)
                {
                    if let BtfFieldKind::Pointer {
                        pointee_name,
                        ..
                    } = &info.kind
                        && trusted_field_load(type_name, info.name)
                    {
                        if let Some(pointee) = pointee_name {
                            let pointee_static = intern_btf_type_name_strict(pointee);
                            // Iter payload pointers are
                            // PTR_TO_BTF_ID_OR_NULL when they're the
                            // iter's "current element" cursor (NULL on
                            // terminating call). Per-subtype rules
                            // mirror the lax-fallback path below; see
                            // its comment for the full table.
                            let is_iter_ctx = type_name.starts_with("bpf_iter__");
                            let is_nullable_iter_payload = is_iter_ctx
                                && match *type_name {
                                    "bpf_iter__task"
                                    | "bpf_iter__cgroup"
                                    | "bpf_iter__tcp"
                                    | "bpf_iter__udp"
                                    | "bpf_iter__unix"
                                    | "bpf_iter__netlink"
                                    | "bpf_iter__bpf_link"
                                    | "bpf_iter__bpf_prog"
                                    | "bpf_iter__bpf_map" => off == 8,
                                    "bpf_iter__task_file"
                                    | "bpf_iter__task_vma" => off == 16,
                                    "bpf_iter__bpf_map_elem"
                                    | "bpf_iter__bpf_sk_storage_map" => off == 16 || off == 24,
                                    _ => false,
                                };
                            return Some(CtxAccessInfo {
                                kind: CtxFieldKind::TrustedPtr {
                                    type_name: pointee_static,
                                    nullable: is_nullable_iter_payload,
                                    trusted: true,
                                    tag_flags: crate::analysis::machine::reg_types::PtrFlags::empty(),
                                },
                                readable: true,
                                writable: false,
                            });
                        } else {
                            // void * iter ctx field (e.g. bpf_iter__bpf_map_elem.
                            // {key,value}). Kernel exposes as PTR_TO_BUF sized to
                            // the iter's target map; we use a generous fixed
                            // bound since map context isn't tracked here.
                            return Some(CtxAccessInfo {
                                kind: CtxFieldKind::AllocMem { mem_size: 4096 },
                                readable: true,
                                writable: false,
                            });
                        }
                    }
                    // Scalar BTF field (INT/ENUM/FLOAT — pt_regs.ax /
                    // .di / etc. are u64 register dumps; raw u64 args
                    // for raw_tracepoint slot loads). Return Scalar so
                    // downstream arithmetic doesn't hit
                    // "Invalid pointer arithmetic" on a bogus ptr type.
                    // Closes loop1::nested_loops (PT_REGS_RC(ctx)→m;
                    // m * i was failing under the lax TrustedPtr
                    // fallback).
                    if matches!(info.kind, BtfFieldKind::Scalar) {
                        return Some(CtxAccessInfo {
                            kind: CtxFieldKind::Scalar,
                            readable: true,
                            writable: false,
                        });
                    }
                }
                // Fallback for non-allowlisted iter / sk_reuseport ctx
                // fields: scalar for non-pointer-sized reads, lax
                // TrustedPtr for 8-byte loads. For BPF_PROG-wrapped
                // iter programs whose `bpf_iter__<subtype>` struct
                // isn't in the program's BTF (compiled-out as
                // unused — the wrapper accesses ctx fields by raw
                // offset, not by named member), the convention is:
                //   offset 0 → bpf_iter_meta *
                //   offset 8 → struct <payload> *
                // Pick the payload struct name from the SEC subtype via
                // a small table covering the iter classes our corpus
                // exercises. Closes cgroup_hierarchical_stats::dumper
                // (subtype "cgroup" → field-8 pointee = "cgroup",
                // accepted by `cgroup_rstat_flush`'s PtrToCgroup arg
                // validator). Other subtypes fall back to
                // TrustedPtr{"unknown"} which still keeps the chain
                // typed.
                if size == 8 {
                    let pointee_name: &'static str = if off == 0 {
                        "bpf_iter_meta"
                    } else if off == 8 {
                        match *type_name {
                            "bpf_iter__cgroup" => "cgroup",
                            "bpf_iter__task" => "task_struct",
                            "bpf_iter__task_file" => "task_struct",
                            "bpf_iter__task_vma" => "task_struct",
                            "bpf_iter__bpf_map" => "bpf_map",
                            "bpf_iter__bpf_link" => "bpf_link",
                            "bpf_iter__bpf_prog" => "bpf_prog",
                            "bpf_iter__tcp" => "sock_common",
                            "bpf_iter__udp" => "udp_sock",
                            "bpf_iter__unix" => "unix_sock",
                            "bpf_iter__netlink" => "netlink_sock",
                            "bpf_iter__sockmap" => "bpf_map",
                            "bpf_iter__ksym" => "kallsym_iter",
                            "bpf_iter__bpf_sk_storage_map" => "bpf_map",
                            _ => "unknown",
                        }
                    } else {
                        "unknown"
                    };
                    // Kernel iter `ctx_arg_info[N].reg_type` is
                    // `PTR_TO_BTF_ID_OR_NULL` for the iter's "current
                    // element" pointer — the iter sends a final NULL
                    // terminating call so the program can do per-iter
                    // cleanup. Per-subtype: single-element iters
                    // (task, cgroup, tcp, udp, unix, netlink, bpf_map,
                    // bpf_link, bpf_prog, sockmap, …) put the nullable
                    // payload at offset 8. Multi-pointer iters
                    // (task_file, task_vma, bpf_map_elem) have a
                    // mixture: a non-null target/owner at offset 8
                    // and the nullable per-element fields after.
                    // Encode via a per-subtype non-null offset set.
                    // Closes bpf_iter_test_kern3::dump_task without
                    // regressing bpf_iter_bpf_hash_map (where map at
                    // offset 8 is the iter target, never null).
                    let non_null_payload_offsets: &[i16] = match *type_name {
                        // task/cgroup/sock/etc: single-element, payload
                        // at offset 8 is the iter cursor (NULL on
                        // terminating call).
                        "bpf_iter__task"
                        | "bpf_iter__cgroup"
                        | "bpf_iter__tcp"
                        | "bpf_iter__udp"
                        | "bpf_iter__unix"
                        | "bpf_iter__netlink"
                        | "bpf_iter__bpf_link"
                        | "bpf_iter__bpf_prog"
                        | "bpf_iter__bpf_map" => &[],
                        // task_file / task_vma: offset 8 is task
                        // (parent, never null while iter is alive),
                        // offset 16 is the file/vma cursor (nullable).
                        "bpf_iter__task_file" | "bpf_iter__task_vma" => &[8],
                        // bpf_map_elem: offset 8 is the target map
                        // (never null), key/value at 16/24 are
                        // nullable.
                        "bpf_iter__bpf_map_elem" | "bpf_iter__bpf_sk_storage_map" => &[8],
                        // Sockmap and others: keep current non-null
                        // typing (no test currently exercises a NULL
                        // payload deref outside of single-element).
                        _ => &[0, 8, 16, 24],
                    };
                    let nullable = off != 0 && !non_null_payload_offsets.contains(&off);
                    return Some(CtxAccessInfo {
                        kind: CtxFieldKind::TrustedPtr {
                            type_name: pointee_name,
                            nullable,
                            trusted: true,
                            tag_flags: crate::analysis::machine::reg_types::PtrFlags::empty(),
                        },
                        readable: true,
                        writable: false,
                    });
                }
                return Some(CtxAccessInfo {
                    kind: CtxFieldKind::Scalar,
                    readable: true,
                    writable: false,
                });
            }
        }
    }

    if matches!(
        prog_kind,
        ProgramKind::StructOps
            | ProgramKind::Lsm
            | ProgramKind::Tracing
            | ProgramKind::Tracepoint
            | ProgramKind::RawTracepoint
            | ProgramKind::RawTracepointWritable
    ) && size == 8
        && off >= 0
        && off % 8 == 0
    {
        let idx = (off / 8) as usize;
        if let Some(args) = env.ctx.entry_args.as_ref() {
            if idx < args.len() {
                use crate::analysis::machine::context::EntryArg;
                // tp_btf attach targets carry per-arg PTR_MAYBE_NULL in
                // the kernel's tracepoint BTF (which we don't ship). The
                // BPF program's declared arg type loses that flag — e.g.
                // `BPF_PROG(h, struct foo *nullable_ctx)` resolves to
                // TrustedPtr{nullable:false} from our BTF resolver, but
                // the tracepoint marks slot N as nullable. Consult the
                // static (target, idx) table so the kernel's
                // "trusted_ptr_or_null_" rejection lands.
                let nullable_from_table = matches!(
                    env.ctx.attach_flavor.as_deref(),
                    Some("tp_btf") | Some("raw_tp") | Some("raw_tp.w")
                ) && env
                    .ctx
                    .attach_subtype
                    .as_deref()
                    .map(|tp| tp_btf_arg_is_maybe_null(tp, idx as u8))
                    .unwrap_or(false);
                let attach_trusted =
                    entry_arg_trusted_for_attach(prog_kind, env.ctx.attach_flavor.as_deref());
                let kind = match &args[idx] {
                    EntryArg::Scalar => CtxFieldKind::Scalar,
                    EntryArg::TrustedPtrBtfId { type_name, nullable } => {
                        CtxFieldKind::TrustedPtr {
                            type_name,
                            nullable: *nullable || nullable_from_table,
                            trusted: attach_trusted,
                            tag_flags: crate::analysis::machine::reg_types::PtrFlags::empty(),
                        }
                    }
                    EntryArg::BoundedScalar { lo, hi } => {
                        CtxFieldKind::BoundedScalar { lo: *lo, hi: *hi }
                    }
                    EntryArg::TrustedRefcountedTask { ref_id } => {
                        CtxFieldKind::RefcountedTask { ref_id: *ref_id }
                    }
                };
                return Some(CtxAccessInfo {
                    kind,
                    readable: true,
                    writable: false,
                });
            }
        }
        // fallback for fentry/LSM/tp_btf where
        // `resolve_func_args` returns the BPF_PROG-wrapper signature
        // rather than the user-declared args (the kernel resolves these
        // from the attach target's vmlinux BTF, which we don't ship).
        // Surface ctx-array slot loads as a "trusted unknown pointer" —
        // the access path then accepts any field read off
        // it via the `type_name == "unknown"` lax policy. Loose but
        // sound: the kernel accepts everything we'd accept here.
        if !matches!(prog_kind, ProgramKind::StructOps) {
            // tp_btf-specific: a few raw-tracepoint targets pass args
            // marked PTR_MAYBE_NULL in the kernel's tracepoint BTF (e.g.
            // sched_pi_setprio's `pi_task` is the inheritor of a PI lock
            // and may legitimately be NULL). The kernel rejects deref
            // before null-check with "invalid mem access
            // 'trusted_ptr_or_null_'" — we mirror this via a static
            // (target, arg_idx) table since we don't ship vmlinux BTF.
            let nullable = matches!(
                env.ctx.attach_flavor.as_deref(),
                Some("tp_btf") | Some("raw_tp") | Some("raw_tp.w")
            ) && env
                .ctx
                .attach_subtype
                .as_deref()
                .map(|tp| tp_btf_arg_is_maybe_null(tp, (off / 8) as u8))
                .unwrap_or(false);
            // BTF TYPE_TAG flags from the attach-target's kernel BTF
            // (USER / PERCPU). We don't ship vmlinux/module BTF, so the
            // table in runner.rs mirrors the small set of attach targets
            // the test corpus exercises. arg_idx is kernel-side
            // (0 = first user-declared arg), matching `off / 8`.
            let tag_flags = crate::testing::attach_rules::tracing_attach_arg_tag_flags(
                env.ctx.attach_subtype.as_deref(),
                (off / 8) as u8,
            );
            // A6: per-attach-target arg-kind override. The lax
            // TrustedPtr default over-types scalar slots (int / short /
            // char / __u64) as pointers, so downstream comparisons
            // like `c == 18` look like pointer arithmetic. The
            // ATTACH_TARGET_ARG_KINDS table flips known-scalar slots
            // to CtxFieldKind::Scalar; unmapped slots keep the lax
            // pointer fallback.
            if matches!(
                crate::testing::attach_rules::tracing_attach_arg_kind(
                    env.ctx.attach_subtype.as_deref(),
                    (off / 8) as u8,
                ),
                Some(crate::testing::attach_rules::TracingArgKind::Scalar)
            ) {
                return Some(CtxAccessInfo {
                    kind: CtxFieldKind::Scalar,
                    readable: true,
                    writable: false,
                });
            }
            let attach_trusted =
                entry_arg_trusted_for_attach(prog_kind, env.ctx.attach_flavor.as_deref());
            return Some(CtxAccessInfo {
                kind: CtxFieldKind::TrustedPtr {
                    type_name: "unknown",
                    nullable,
                    trusted: attach_trusted,
                    tag_flags,
                },
                readable: true,
                writable: false,
            });
        }
    }

    // for the BPF_PROG-style ctx prog kinds, the ctx is a
    // BTF arg array. Only 8-byte aligned 8-byte loads are valid; narrow
    // loads, misaligned loads, or negative offsets must reject. Without
    // this guard, those fall through to the SkBuff/etc. fallback below
    // and are silently accepted.
    if matches!(
        prog_kind,
        ProgramKind::StructOps
            | ProgramKind::Lsm
            | ProgramKind::Tracing
            | ProgramKind::Tracepoint
            | ProgramKind::RawTracepoint
            | ProgramKind::RawTracepointWritable
    ) {
        return None;
    }

    // netfilter ctx is `struct bpf_nf_ctx { state; skb; }` —
    // only 8-byte loads at off 0 (state) and off 8 (skb) are valid.
    if prog_kind == ProgramKind::Netfilter {
        if size == 8 && (off == 0 || off == 8) {
            // bpf_nf_ctx { state @ 0; skb @ 8; }. Type the loaded
            // value as the named struct so subsequent field reads
            // (e.g. `state->pf` in
            // `verifier_netfilter_ctx::with_valid_ctx_access_test6`)
            // type-check. Writes through the loaded pointer remain
            // rejected: PtrToBtfId{<name>, TRUSTED} stores fall into
            // the access.rs check_store arm, which rejects since
            // nf_hook_state / sk_buff aren't in mem_region_model
            // (closes `with_invalid_ctx_access_test5`'s
            // `state->sk = NULL` rejection).
            let type_name = if off == 0 { "nf_hook_state" } else { "sk_buff" };
            return Some(CtxAccessInfo {
                kind: CtxFieldKind::TrustedPtr {
                    type_name,
                    nullable: false,
                    trusted: true,
                    tag_flags: crate::analysis::machine::reg_types::PtrFlags::empty(),
                },
                readable: true,
                writable: false,
            });
        }
        return None;
    }

    // CGROUP_SOCK shares the BpfSock ctx but the kernel gates each
    // `struct bpf_sock` field on the program's expected_attach_type
    // (`__sock_filter_check_attach_type`, net/core/filter.c). The flat
    // BPF_SOCK_FIELDS table can't express that, so deny here the
    // offsets the kernel rejects for this attach subtype:
    //   - sock_create / sock_release: src_ip4(24)/src_ip6(28..44)/
    //     src_port(44..48) are NOT accessible (only bound_dev_if/mark/
    //     priority full-access + the unrestricted read-only fields are).
    //     Without this, `*(u16*)(bpf_sock + 44)` under
    //     SEC("cgroup/sock_create") was wrongly accepted (FALSE-ACCEPT:
    //     verifier_sock::sock_create_read_src_port — the kernel rejects
    //     it, src_port is only readable under INET4/6_POST_BIND).
    //   - post_bind4: mark(16) + src_ip6(28..44) [IPv4-only].
    //   - post_bind6: mark(16) + src_ip4(24) [IPv6-only].
    // (The kernel additionally denies bound_dev_if(0)/priority(20) under
    // post_bind*; not modeled here.)
    if prog_kind == ProgramKind::CgroupSock {
        if let Some(sub) = env.ctx.attach_subtype.as_deref() {
            let denied = match sub {
                "sock_create" | "sock_release" => (24..48).contains(&off),
                "post_bind4" => off == 16 || (28..44).contains(&off),
                "post_bind6" => off == 16 || off == 24,
                _ => false,
            };
            if denied {
                return None;
            }
        }
    }

    let ctx_kind = match prog_kind {
        ProgramKind::Tracing => match (env.ctx.attach_kind, env.ctx.kfunc.as_deref()) {
            (AttachKind::TraceIter, Some("task")) => ContextKind::IterTask,
            _ => ContextKind::SkBuff,
        },
        _ => prog_kind.context_kind(),
    };

    // Check scratch regions first (e.g., cb)
    if let Some(info) = lookup_region(ctx_kind, off, size) {
        let mut info = info;
        apply_prog_type_overrides(prog_kind, off, &mut info);
        return Some(info);
    }

    let (base, extended) = match get_field_tables(
        ctx_kind,
        prog_kind,
        env.ctx.attach_subtype.as_deref(),
    ) {
        Some(tables) => tables,
        None => {
            return Some(CtxAccessInfo {
                kind: CtxFieldKind::Scalar,
                readable: true,
                writable: false,
            });
        }
    };

    // Search base fields, then extended fields
    let mut info = lookup_field(base, off, size).or_else(|| lookup_field(extended, off, size))?;

    apply_prog_type_overrides(prog_kind, off, &mut info);
    Some(info)
}

/// Check if a context field is readable at the given offset and size.
///
/// This is a convenience wrapper around `validate_ctx_access` for cases
/// where you only need to check validity without the field info.
pub fn is_valid_ctx_read(env: &VerifierEnv, off: i16, size: i64) -> bool {
    validate_ctx_access(env, off, size)
        .map(|info| info.readable)
        .unwrap_or(false)
}

/// Check if a context field is writable at the given offset and size.
///
/// Returns true only if the access is valid AND the field is writable.
pub fn is_valid_ctx_write(env: &VerifierEnv, off: i16, size: i64) -> bool {
    validate_ctx_access(env, off, size)
        .map(|info| info.writable)
        .unwrap_or(false)
}
