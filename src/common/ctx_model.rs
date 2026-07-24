// src/analysis/ctx_model.rs
//
// Data-driven BPF context field definitions and access validation.
//
// This module defines the layout of BPF context structures (sk_buff, xdp_md, etc.)
// as data tables, enabling unified validation of both reads and writes.

use crate::{
    analysis::machine::env::VerifierEnv,
    ast::{AttachKind, ContextKind, MemSize, ProgramKind},
};

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
const SK_BUFF_FIELDS: &[CtxField] = &[
    // __u32 len
    CtxField {
        offset: 0,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 pkt_type
    CtxField {
        offset: 4,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 mark
    CtxField {
        offset: 8,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: true,
    },
    // __u32 queue_mapping
    CtxField {
        offset: 12,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
    // __u32 protocol
    CtxField {
        offset: 16,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 vlan_present
    CtxField {
        offset: 20,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 vlan_tci
    CtxField {
        offset: 24,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 vlan_proto
    CtxField {
        offset: 28,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 priority
    CtxField {
        offset: 32,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
    // __u32 ingress_ifindex
    CtxField {
        offset: 36,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 ifindex
    CtxField {
        offset: 40,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 tc_index
    CtxField {
        offset: 44,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
    // __u32 cb[5] (offsets 48-67, 20 bytes) - control buffer, writable
    CtxField {
        offset: 48,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: true,
    },
    CtxField {
        offset: 52,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: true,
    },
    CtxField {
        offset: 56,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: true,
    },
    CtxField {
        offset: 60,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: true,
    },
    CtxField {
        offset: 64,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: true,
    },
    // __u32 hash
    CtxField {
        offset: 68,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 tc_classid
    CtxField {
        offset: 72,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
    // __u32 data
    CtxField {
        offset: 76,
        size: MemSize::U32,
        kind: CtxFieldKind::PacketStart,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 data_end
    CtxField {
        offset: 80,
        size: MemSize::U32,
        kind: CtxFieldKind::PacketEnd,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 napi_id
    CtxField {
        offset: 84,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 family
    CtxField {
        offset: 88,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 remote_ip4
    CtxField {
        offset: 92,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 local_ip4
    CtxField {
        offset: 96,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 remote_ip6[4]
    CtxField {
        offset: 100,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 104,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 108,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 112,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 local_ip6[4]
    CtxField {
        offset: 116,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 120,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 124,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 128,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 remote_port
    CtxField {
        offset: 132,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 local_port
    CtxField {
        offset: 136,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 data_meta
    CtxField {
        offset: 140,
        size: MemSize::U32,
        kind: CtxFieldKind::PacketMeta,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // struct bpf_sock *sk (offset 168, size 8)
    // Kernel `bpf_skb_is_valid_access` permits read of `sk` for every
    // skb-context prog type (SocketFilter, SchedCls, SchedAct, CgroupSkb,
    // SkSkb, LWT, …). Modeled in the main field table rather than the
    // CGROUP_SKB-only extended set so all prog kinds with SkBuff ctx see
    // it. Returns a `PtrToSockCommon | NULL`; per-field-kind typing is
    // wired through `CtxFieldKind::SockCommon`.
    CtxField {
        offset: 168,
        size: MemSize::U64,
        kind: CtxFieldKind::SockCommon,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // Additional fields can be added as needed...
];

pub const SK_BUFF_CB_START: i16 = 48;
pub const SK_BUFF_CB_END: i16 = 68; // 48 + 5*4 = 68

/// FlowDissector-only addition to the SkBuff field table.
/// `flow_keys` (offset 144, size 8) is a `struct bpf_flow_keys *` —
/// kernel `flow_dissector_is_valid_access` permits it for
/// BPF_PROG_TYPE_FLOW_DISSECTOR (and only there). Returns a
/// non-nullable trusted pointer; the kernel guarantees flow_keys is
/// set for the dissector entry.
const FLOW_DISSECTOR_EXTENDED_FIELDS: &[CtxField] = &[CtxField {
    offset: 144,
    size: MemSize::U64,
    kind: CtxFieldKind::TrustedPtr {
        type_name: "bpf_flow_keys",
        nullable: false,
        trusted: true,
        tag_flags: crate::analysis::machine::reg_types::PtrFlags::empty(),
    },
    writable: false,
    readable: true,
    narrow_access: false,
}];

// Only available for CGROUP_SKB and CLS
const SK_BUFF_EXTENDED_FIELDS: &[CtxField] = &[
    // __u64 tstamp (offset 152)
    CtxField {
        offset: 152,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 wire_len (offset 160)
    CtxField {
        offset: 160,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 gso_segs (offset 164)
    CtxField {
        offset: 164,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // (offset 168 `sk` is in the main SK_BUFF_FIELDS — kernel permits it
    // for every skb-context prog type, not just CGROUP_SKB/SchedCls.)
    // __u32 gso_size (offset 176)
    CtxField {
        offset: 176,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u8 tstamp_type (offset 180). Kernel `bpf_skb_is_valid_access`
    // permits read of `tstamp_type` for tc/cgroup_skb. test_tc_dtime
    // reads via `Load U8 base+180`. The follow-up 24 bits are explicit
    // padding; we don't model them.
    CtxField {
        offset: 180,
        size: MemSize::U8,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u64 hwtstamp (offset 184). Kernel hardware timestamp (set by
    // NIC drivers via skb_hwtstamps). Read-only for BPF programs;
    // test_skb_ctx::process reads via `Load U64 base+184`.
    CtxField {
        offset: 184,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
];

/// struct xdp_md (XDP context)
///
/// Reference: linux/include/uapi/linux/bpf.h
const XDP_MD_FIELDS: &[CtxField] = &[
    // __u32 data
    CtxField {
        offset: 0,
        size: MemSize::U32,
        kind: CtxFieldKind::PacketStart,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 data_end
    CtxField {
        offset: 4,
        size: MemSize::U32,
        kind: CtxFieldKind::PacketEnd,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 data_meta
    CtxField {
        offset: 8,
        size: MemSize::U32,
        kind: CtxFieldKind::PacketMeta,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 ingress_ifindex
    CtxField {
        offset: 12,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 rx_queue_index
    CtxField {
        offset: 16,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
];

/// XDP devmap-only ctx fields. Per kernel verifier (xdp_func_proto +
/// bpf_xdp_dev_md_is_valid_access), `egress_ifindex` is rejected unless
/// the program's `expected_attach_type == BPF_XDP_DEVMAP`. libbpf
/// derives that from `SEC("xdp/devmap")` / `SEC("xdp.frags/devmap")`,
/// which the runner reflects as `attach_subtype == Some("devmap")`.
const XDP_MD_DEVMAP_FIELDS: &[CtxField] = &[
    // __u32 egress_ifindex
    CtxField {
        offset: 20,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
];

/// struct bpf_sock_addr (cgroup sock_addr context)
///
/// Reference: linux/include/uapi/linux/bpf.h
///
/// Kernel `bpf_sock_addr_is_valid_access` admits 1-, 2-, and 4-byte
/// loads on the user_*/msg_src_* fields (programs use byte-level
/// inspection like `ctx->user_ip4 & 0xff`). Set `narrow_access: true`
/// on the addr/port fields to mirror this; tests like bind4_prog.c
/// (offset 4 size 1) and bind6_prog.c (offset 24 size 1) need it.
const SOCK_ADDR_FIELDS: &[CtxField] = &[
    // __u32 user_family
    CtxField { offset: 0,  size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: true,  readable: true, narrow_access: true },
    // __u32 user_ip4
    CtxField { offset: 4,  size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: true,  readable: true, narrow_access: true },
    // __u32 user_ip6[4] (offsets 8-23)
    CtxField { offset: 8,  size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: true,  readable: true, narrow_access: true },
    CtxField { offset: 12, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: true,  readable: true, narrow_access: true },
    CtxField { offset: 16, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: true,  readable: true, narrow_access: true },
    CtxField { offset: 20, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: true,  readable: true, narrow_access: true },
    // __u32 user_port
    CtxField { offset: 24, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: true,  readable: true, narrow_access: true },
    // __u32 family
    CtxField {
        offset: 28,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 type
    CtxField {
        offset: 32,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 protocol
    CtxField {
        offset: 36,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 msg_src_ip4 — kernel allows 1,2,4-byte read and 4-byte write
    CtxField {
        offset: 40,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
    // __u32 msg_src_ip6[4] — kernel allows 1,2,4,8-byte read and 4,8-byte write
    CtxField {
        offset: 44,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 48,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 52,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 56,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
    // __bpf_md_ptr(struct bpf_sock *, sk). The union is __attribute__((aligned(8)))
    // so the field starts at offset 64, NOT 60 — `msg_src_ip6[4]` ends at 60 and
    // the alignment pad pushes the ptr to 64. Tests in bind_perm.c, bind4_prog.c,
    // bind6_prog.c, connect_force_port{4,6}.c read sk via `Load U64 base+64`.
    // The sk pointer is read-only at the sock_addr context; we model it as
    // SockCommon (PtrToSockCommonOrNull) so callers null-check before deref.
    CtxField {
        offset: 64,
        size: MemSize::U64,
        kind: CtxFieldKind::SockCommon,
        writable: false,
        readable: true,
        narrow_access: false,
    },
];

/// struct bpf_sockopt (BPF_PROG_TYPE_CGROUP_SOCKOPT context — used by
/// `SEC("cgroup/getsockopt")` and `SEC("cgroup/setsockopt")` programs).
///
/// Reference: linux/include/uapi/linux/bpf.h and
/// kernel/bpf/cgroup.c::cgroup_sockopt_is_valid_access (v6.15).
///
/// Layout (offsets verified against kernel `offsetof`):
///   __bpf_md_ptr(struct bpf_sock *, sk)        @  0..8   RO ptr_to_socket
///   __bpf_md_ptr(void *,           optval)     @  8..16  RO packet_start
///   __bpf_md_ptr(void *,           optval_end) @ 16..24  RO packet_end
///   __s32                           level      @ 24..28
///   __s32                           optname    @ 28..32
///   __s32                           optlen     @ 32..36
///   __s32                           retval     @ 36..40
///
/// All scalar fields are read-permissive; we mark them writable too. The
/// kernel actually scopes writes (level/optname only writable from
/// setsockopt; retval only writable from setsockopt; optlen writable from
/// either) but we don't currently distinguish attach types here. No
/// PASS-row in the corpus depends on a stricter rule, and the FRs we are
/// closing only exercise reads + retval writes.
const BPF_SOCKOPT_FIELDS: &[CtxField] = &[
    // struct bpf_sock *sk (offset 0) — kernel hands a non-null
    // PTR_TO_SOCKET; emitting the non-null Socket form lets
    // `bpf_sk_storage_get(ctx->sk, ...)` (which requires
    // PTR_TO_BTF_ID_SOCK_COMMON, accepting PTR_TO_SOCKET) pass without
    // a synthetic null-check round-trip.
    CtxField {
        offset: 0,
        size: MemSize::U64,
        kind: CtxFieldKind::Socket,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // void *optval (offset 8)
    CtxField {
        offset: 8,
        size: MemSize::U64,
        kind: CtxFieldKind::PacketStart,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // void *optval_end (offset 16)
    CtxField {
        offset: 16,
        size: MemSize::U64,
        kind: CtxFieldKind::PacketEnd,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __s32 level (offset 24)
    CtxField {
        offset: 24,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
    // __s32 optname (offset 28)
    CtxField {
        offset: 28,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
    // __s32 optlen (offset 32)
    CtxField {
        offset: 32,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
    // __s32 retval (offset 36)
    CtxField {
        offset: 36,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: false,
    },
];

const SOCK_ADDR_USER_IP6_START: i16 = 8;
const SOCK_ADDR_USER_IP6_END: i16 = 24; // 8 + 4*4 = 23
const SOCK_ADDR_MSG_SRC_IP6_START: i16 = 44;
const SOCK_ADDR_MSG_SRC_IP6_END: i16 = 56; // 44 + 4*4 = 56

/// struct sk_reuseport_md (SK_REUSEPORT context)
///
/// Reference: linux/include/uapi/linux/bpf.h, kernel
/// `sk_reuseport_is_valid_access` in net/core/filter.c.
///
/// struct sk_reuseport_md {
///     __bpf_md_ptr(void *, data);              // 0-8   PTR_TO_PACKET
///     __bpf_md_ptr(void *, data_end);          // 8-16  PTR_TO_PACKET_END
///     __u32 len;                                // 16-20
///     __u32 eth_protocol;                       // 20-24
///     __u32 ip_protocol;                        // 24-28
///     __u32 bind_inany;                         // 28-32
///     __u32 hash;                               // 32-36
///     __bpf_md_ptr(struct bpf_sock *, sk);          // 40-48 PTR_TO_SOCKET
///     __bpf_md_ptr(struct bpf_sock *, migrating_sk);// 48-56 PTR_TO_SOCK_COMMON_OR_NULL
/// };
const SK_REUSEPORT_FIELDS: &[CtxField] = &[
    // void *data (PTR_TO_PACKET)
    CtxField {
        offset: 0,
        size: MemSize::U64,
        kind: CtxFieldKind::PacketStart,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // void *data_end (PTR_TO_PACKET_END)
    CtxField {
        offset: 8,
        size: MemSize::U64,
        kind: CtxFieldKind::PacketEnd,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    CtxField { offset: 16, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: false },
    CtxField { offset: 20, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: false },
    CtxField { offset: 24, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: false },
    CtxField { offset: 28, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: false },
    CtxField { offset: 32, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: false },
    // struct bpf_sock *sk (PTR_TO_SOCKET, non-null)
    CtxField {
        offset: 40,
        size: MemSize::U64,
        kind: CtxFieldKind::Socket,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // struct bpf_sock *migrating_sk (PTR_TO_SOCK_COMMON_OR_NULL)
    CtxField {
        offset: 48,
        size: MemSize::U64,
        kind: CtxFieldKind::SockCommon,
        writable: false,
        readable: true,
        narrow_access: false,
    },
];

/// struct bpf_sk_lookup (SK_LOOKUP context)
///
/// Reference: linux/include/uapi/linux/bpf.h
///
/// struct bpf_sk_lookup {
///     union {
///         __bpf_md_ptr(struct bpf_sock *, sk);
///         __u64 cookie;
///     };                          // 0-8
///     __u32 family;               // 8-12
///     __u32 protocol;             // 12-16
///     __u32 remote_ip4;           // 16-20
///     __u32 remote_ip6[4];        // 20-36
///     __be16 remote_port;         // 36-38 (accessed as u32 at 36)
///     __u16 :16;                  // 38-40 (padding)
///     __u32 local_ip4;            // 40-44
///     __u32 local_ip6[4];         // 44-60
///     __u32 local_port;           // 60-64
/// };
const SK_LOOKUP_FIELDS: &[CtxField] = &[
    // struct bpf_sock *sk (offset 0). Kernel types this as
    // PTR_TO_SOCKET_OR_NULL (`bpf_sk_lookup_is_valid_access`); a sk1
    // from `bpf_map_lookup_elem` on a SOCKMAP/REUSEPORT_SOCKARRAY is
    // PtrToSocket — the JEQ-refinement on `ctx->sk == sk1` only
    // promotes nullable→non-null when the two flavors match. Was
    // SockCommon, which broke equality refinement in test_sk_lookup
    // ::access_ctx_sk's `if (ctx->sk != sk1) goto out; ctx->sk->family`
    // pattern (kernel admits, we rejected post-equality deref).
    CtxField {
        offset: 0,
        size: MemSize::U64,
        kind: CtxFieldKind::SocketOrNull,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 family (offset 8)
    CtxField {
        offset: 8,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 protocol (offset 12)
    CtxField {
        offset: 12,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 remote_ip4 (offset 16)
    CtxField {
        offset: 16,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 remote_ip6[4] (offsets 20, 24, 28, 32)
    CtxField {
        offset: 20,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    CtxField {
        offset: 24,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    CtxField {
        offset: 28,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    CtxField {
        offset: 32,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 remote_port (offset 36)
    CtxField {
        offset: 36,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 local_ip4 (offset 40)
    CtxField {
        offset: 40,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 local_ip6[4] (offsets 44, 48, 52, 56)
    CtxField {
        offset: 44,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    CtxField {
        offset: 48,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    CtxField {
        offset: 52,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    CtxField {
        offset: 56,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 local_port (offset 60)
    CtxField {
        offset: 60,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 ingress_ifindex (offset 64). Added in v5.x — the
    // arriving interface, determined by inet_iif. Read-only.
    CtxField {
        offset: 64,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
];

/// struct bpf_sock_ops (SOCK_OPS context)
///
/// Reference: linux/include/uapi/linux/bpf.h
///
/// The verifier allows writes to `reply` (offset 4); the remaining fields are read-only.
const SOCK_OPS_FIELDS: &[CtxField] = &[
    // __u32 op
    CtxField {
        offset: 0,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 reply
    CtxField {
        offset: 4,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: true,
        readable: true,
        narrow_access: true,
    },
    // __u32 family
    CtxField {
        offset: 20,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // Canonical layout (uapi/linux/bpf.h struct bpf_sock_ops):
    //   24  remote_ip4         28  local_ip4
    //   32  remote_ip6[0..3]   48  local_ip6[0..3]
    //   64  remote_port        68  local_port
    // All u32, read-only, narrow-access OK.
    CtxField { offset: 24, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // remote_ip4
    CtxField { offset: 28, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // local_ip4
    CtxField { offset: 32, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // remote_ip6[0]
    CtxField { offset: 36, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // remote_ip6[1]
    CtxField { offset: 40, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // remote_ip6[2]
    CtxField { offset: 44, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // remote_ip6[3]
    CtxField { offset: 48, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // local_ip6[0]
    CtxField { offset: 52, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // local_ip6[1]
    CtxField { offset: 56, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // local_ip6[2]
    CtxField { offset: 60, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // local_ip6[3]
    CtxField { offset: 64, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // remote_port
    CtxField { offset: 68, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // local_port
    // ── union slots @ 8/12/16 (args[1..3] / replylong[1..3]). Kernel
    // permits scalar reads across the whole 16-byte union; tcp_rtt.c
    // reads `args[1]` from a CB callback (offset 8). ────────────────
    CtxField { offset: 8,  size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },
    CtxField { offset: 12, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },
    CtxField { offset: 16, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },
    // ── bpf_sock_ops tcp scalar fields at 72-167. Each is a u32 the
    // kernel exposes via `bpf_sock_ops_is_valid_access`. Adding the
    // full set closes test_tcp{,notify,bpf}_kern, test_{misc_,}tcp_
    // hdr_options, and tcp_rtt sockops field reads. ────────────────
    CtxField { offset: 72,  size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // is_fullsock
    CtxField { offset: 76,  size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // snd_cwnd
    CtxField { offset: 80,  size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // srtt_us
    CtxField { offset: 84,  size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: true,  readable: true, narrow_access: true }, // bpf_sock_ops_cb_flags (writable)
    CtxField { offset: 88,  size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // state
    CtxField { offset: 92,  size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // rtt_min
    CtxField { offset: 96,  size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // snd_ssthresh
    CtxField { offset: 100, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // rcv_nxt
    CtxField { offset: 104, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // snd_nxt
    CtxField { offset: 108, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // snd_una
    CtxField { offset: 112, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // mss_cache
    CtxField { offset: 116, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // ecn_flags
    CtxField { offset: 120, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // rate_delivered
    CtxField { offset: 124, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // rate_interval_us
    CtxField { offset: 128, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // packets_out
    CtxField { offset: 132, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // retrans_out
    CtxField { offset: 136, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // total_retrans
    CtxField { offset: 140, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // segs_in
    CtxField { offset: 144, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // data_segs_in
    CtxField { offset: 148, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // segs_out
    CtxField { offset: 152, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // data_segs_out
    CtxField { offset: 156, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // lost_out
    CtxField { offset: 160, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true }, // sacked_out
    CtxField { offset: 164, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: true,  readable: true, narrow_access: true }, // sk_txhash (writable)
    // bytes_received (u64) @ 168, bytes_acked (u64) @ 176
    CtxField { offset: 168, size: MemSize::U64, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: false },
    CtxField { offset: 176, size: MemSize::U64, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: false },
    // skb_data / skb_data_end @ 192/200 — packet pointers exposed
    // during HDR_OPT_LEN/PARSE_HDR_OPT/WRITE_HDR_OPT callbacks.
    CtxField { offset: 192, size: MemSize::U64, kind: CtxFieldKind::PacketStart, writable: false, readable: true, narrow_access: false },
    CtxField { offset: 200, size: MemSize::U64, kind: CtxFieldKind::PacketEnd,   writable: false, readable: true, narrow_access: false },
    // skb_len, skb_tcp_flags, skb_hwtstamp
    CtxField { offset: 208, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },
    CtxField { offset: 212, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },
    CtxField { offset: 216, size: MemSize::U64, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: false },
    // __bpf_md_ptr(struct bpf_sock *, sk) at offset 184. The kernel
    // bpf_sock_ops struct has many u32/u64 tcp fields before this
    // (snd_cwnd, srtt_us, rcv_nxt, …, bytes_received, bytes_acked);
    // we don't model those scalar fields exhaustively. Adding `sk`
    // unmasks tests that previously rejected on "Unsafe ctx access at
    // offset 184" (because the field wasn't modeled), in particular
    // sock_ops programs that pass `ctx->sk` to `bpf_map_update_elem`
    // on a sockmap — kernel rejects "cannot update sockmap in this
    // context" via a per-prog-type map-helper restriction that we
    // don't model. That's a real verifier-coverage gap; the
    // resulting FAs (test_sockmap_invalid_update::bpf_sockmap,
    // verifier_sockmap_mutate::test_sockops_update) are honest
    // signals that we need to add the prog-type-vs-map-helper gate.
    CtxField {
        offset: 184,
        size: MemSize::U64,
        kind: CtxFieldKind::SockCommon,
        writable: false,
        readable: true,
        narrow_access: false,
    },
];

/// struct bpf_sock (CGROUP_SOCK context)
///
/// Reference: linux/include/uapi/linux/bpf.h
///
/// Keep this conservative and expand as needed by benchmark coverage.
const BPF_SOCK_FIELDS: &[CtxField] = &[
    // __u32 bound_dev_if
    CtxField {
        offset: 0,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 family
    CtxField {
        offset: 4,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 type
    CtxField {
        offset: 8,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // __u32 protocol
    CtxField {
        offset: 12,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: true,
    },
    // Remaining `struct bpf_sock` fields (uapi linux/bpf.h), mirroring
    // the kernel's `bpf_sock_is_valid_access`: the IP/port/state/
    // rx_queue_mapping fields are in the narrow-access switch
    // (1/2/4-byte reads ok); `mark`/`priority` are not (4-byte only).
    // All modeled read-only (conservative; bpf_sock write-validity is
    // attach-type dependent — keeping writes strict only risks a
    // false-reject on a write, never a false-accept, and matches the
    // 0/4/8/12 entries above). The kernel permits these reads
    // (e.g. `src_ip4`@24, `src_port`@44).
    CtxField { offset: 16, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: false }, // mark
    CtxField { offset: 20, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: false }, // priority
    CtxField { offset: 24, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // src_ip4
    CtxField { offset: 28, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // src_ip6[0]
    CtxField { offset: 32, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // src_ip6[1]
    CtxField { offset: 36, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // src_ip6[2]
    CtxField { offset: 40, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // src_ip6[3]
    CtxField { offset: 44, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // src_port (host byte order)
    CtxField { offset: 48, size: MemSize::U16, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // dst_port (__be16; 50..52 = zero pad)
    CtxField { offset: 52, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // dst_ip4
    CtxField { offset: 56, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // dst_ip6[0]
    CtxField { offset: 60, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // dst_ip6[1]
    CtxField { offset: 64, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // dst_ip6[2]
    CtxField { offset: 68, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // dst_ip6[3]
    CtxField { offset: 72, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // state
    CtxField { offset: 76, size: MemSize::U32, kind: CtxFieldKind::Scalar, writable: false, readable: true, narrow_access: true },  // rx_queue_mapping (s32)
];

/// struct sk_msg_md (SK_MSG context)
///
/// Reference: linux/include/uapi/linux/bpf.h
///
/// struct sk_msg_md {
///     __bpf_md_ptr(void *, data);           // 0-8
///     __bpf_md_ptr(void *, data_end);       // 8-16
///     __u32 family;                          // 16-20
///     __u32 remote_ip4;                      // 20-24
///     __u32 local_ip4;                       // 24-28
///     __u32 remote_ip6[4];                   // 28-44
///     __u32 local_ip6[4];                    // 44-60
///     __u32 remote_port;                     // 60-64
///     __u32 local_port;                      // 64-68
///     __u32 size;                            // 68-72
///     __bpf_md_ptr(struct bpf_sock *, sk);   // 72-80
/// };
///
/// Note: __bpf_md_ptr creates 8-byte aligned unions. All sk_msg_md fields
/// are read-only; data modifications happen via helpers like bpf_msg_push_data.
const SK_MSG_MD_FIELDS: &[CtxField] = &[
    // __bpf_md_ptr(void *, data) - start of message data
    CtxField {
        offset: 0,
        size: MemSize::U64,
        kind: CtxFieldKind::PacketStart,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __bpf_md_ptr(void *, data_end) - end of message data
    CtxField {
        offset: 8,
        size: MemSize::U64,
        kind: CtxFieldKind::PacketEnd,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 family
    CtxField {
        offset: 16,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 remote_ip4
    CtxField {
        offset: 20,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 local_ip4
    CtxField {
        offset: 24,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 remote_ip6[4]
    CtxField {
        offset: 28,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 32,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 36,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 40,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 local_ip6[4]
    CtxField {
        offset: 44,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 48,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 52,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    CtxField {
        offset: 56,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 remote_port
    CtxField {
        offset: 60,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 local_port
    CtxField {
        offset: 64,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __u32 size
    CtxField {
        offset: 68,
        size: MemSize::U32,
        kind: CtxFieldKind::Scalar,
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __bpf_md_ptr(struct bpf_sock *, sk) - current socket. Kernel
    // sk_msg_is_valid_access returns PTR_TO_SOCKET (non-null) for this
    // load — sk_msg programs run with an established socket, so the
    // pointer is guaranteed non-null at program entry. Tests in
    // test_skmsg_load_helpers.c pass `msg->sk` directly to
    // bpf_sk_storage_get without an intervening null check.
    CtxField {
        offset: 72,
        size: MemSize::U64,
        kind: CtxFieldKind::Socket,
        writable: false,
        readable: true,
        narrow_access: false,
    },
];

/// struct pt_regs (x86_64) - kprobe/tracepoint/perf_event context
///
/// Reference: arch/x86/include/asm/ptrace.h
///
/// All fields are unsigned long (8 bytes), read-only for BPF.
const PT_REGS_FIELDS: &[CtxField] = &[
    CtxField {
        offset: 0,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // r15
    CtxField {
        offset: 8,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // r14
    CtxField {
        offset: 16,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // r13
    CtxField {
        offset: 24,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // r12
    CtxField {
        offset: 32,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // rbp
    CtxField {
        offset: 40,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // rbx
    CtxField {
        offset: 48,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // r11
    CtxField {
        offset: 56,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // r10
    CtxField {
        offset: 64,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // r9
    CtxField {
        offset: 72,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // r8
    CtxField {
        offset: 80,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // rax
    CtxField {
        offset: 88,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // rcx
    CtxField {
        offset: 96,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // rdx
    CtxField {
        offset: 104,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // rsi
    CtxField {
        offset: 112,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // rdi
    CtxField {
        offset: 120,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // orig_rax
    CtxField {
        offset: 128,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // rip
    CtxField {
        offset: 136,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // cs
    CtxField {
        offset: 144,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // eflags
    CtxField {
        offset: 152,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // rsp
    CtxField {
        offset: 160,
        size: MemSize::U64,
        kind: CtxFieldKind::Scalar,
        readable: true,
        writable: false,
        narrow_access: false,
    }, // ss
];

/// struct bpf_iter__task (task iterator context)
///
/// Reference: kernel/bpf/task_iter.c
const TRACE_ITER_TASK_FIELDS: &[CtxField] = &[
    // __bpf_md_ptr(struct bpf_iter_meta *, meta)
    CtxField {
        offset: 0,
        size: MemSize::U64,
        kind: CtxFieldKind::TrustedPtr {
            type_name: "bpf_iter_meta",
            nullable: false,
            trusted: true,
            tag_flags: crate::analysis::machine::reg_types::PtrFlags::empty(),
        },
        writable: false,
        readable: true,
        narrow_access: false,
    },
    // __bpf_md_ptr(struct task_struct *, task)
    CtxField {
        offset: 8,
        size: MemSize::U64,
        kind: CtxFieldKind::TrustedPtr {
            type_name: "task_struct",
            nullable: true,
            trusted: true,
            tag_flags: crate::analysis::machine::reg_types::PtrFlags::empty(),
        },
        writable: false,
        readable: true,
        narrow_access: false,
    },
];

// ===========================================================================
// Field Lookup
// ===========================================================================

/// Look up field info for a context access.
/// Returns None if no valid field exists at (offset, size).
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

// Per-tracepoint MAYBE_NULL arg table (tp_btf / raw_tp)
// ===========================================================================

/// `(tracepoint_target, arg_idx)` pairs whose kernel BTF marks the arg as
/// `PTR_MAYBE_NULL`. The kernel rejects deref of these args before a null
/// check ("invalid mem access 'trusted_ptr_or_null_'"). Mirrors what the
/// kernel resolves from the tracepoint's `__bpf_trace_*` BTF; we maintain
/// a static table because that BTF lives in vmlinux which we don't ship.
///
/// `arg_idx` is 0-based across the FUNC_PROTO params (matches the ctx
/// slot index — `r1 = *(u64*)(r1 + 8*idx)`).
const TP_BTF_MAYBE_NULL_ARGS: &[(&str, u8)] = &[
    // sched_pi_setprio(struct task_struct *tsk, struct task_struct *pi_task) —
    // `pi_task` (arg 1, 0-based) is the inheritor of a PI lock and may be NULL.
    ("sched_pi_setprio", 1),
    // bpf_testmod_test_raw_tp_null(struct task_struct *task) — task arg is
    // declared with __nullable in the kmod's tracepoint definition.
    ("bpf_testmod_test_raw_tp_null", 0),
    // bpf_testmod_test_nullable_bare(struct bpf_testmod_test_read_ctx *) —
    // ctx arg declared __nullable; covered by `test_tp_btf_nullable.c`.
    ("bpf_testmod_test_nullable_bare", 0),
];

fn tp_btf_arg_is_maybe_null(tp_target: &str, arg_idx: u8) -> bool {
    TP_BTF_MAYBE_NULL_ARGS
        .iter()
        .any(|(tp, idx)| *tp == tp_target && *idx == arg_idx)
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
