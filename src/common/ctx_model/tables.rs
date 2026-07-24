// Static context-access tables: per-context-kind `CtxField` layouts
// (mirroring the kernel's `*_is_valid_access` / convert_ctx_access field
// rules) plus the tp_btf per-target MAYBE_NULL arg table. Pure data —
// lookup logic lives in the parent module.

use super::{CtxField, CtxFieldKind};
use crate::ast::MemSize;

pub(super) const SK_BUFF_FIELDS: &[CtxField] = &[
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
pub(super) const FLOW_DISSECTOR_EXTENDED_FIELDS: &[CtxField] = &[CtxField {
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
pub(super) const SK_BUFF_EXTENDED_FIELDS: &[CtxField] = &[
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
pub(super) const XDP_MD_FIELDS: &[CtxField] = &[
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
pub(super) const XDP_MD_DEVMAP_FIELDS: &[CtxField] = &[
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
pub(super) const SOCK_ADDR_FIELDS: &[CtxField] = &[
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
pub(super) const BPF_SOCKOPT_FIELDS: &[CtxField] = &[
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

pub(super) const SOCK_ADDR_USER_IP6_START: i16 = 8;
pub(super) const SOCK_ADDR_USER_IP6_END: i16 = 24; // 8 + 4*4 = 23
pub(super) const SOCK_ADDR_MSG_SRC_IP6_START: i16 = 44;
pub(super) const SOCK_ADDR_MSG_SRC_IP6_END: i16 = 56; // 44 + 4*4 = 56

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
pub(super) const SK_REUSEPORT_FIELDS: &[CtxField] = &[
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
pub(super) const SK_LOOKUP_FIELDS: &[CtxField] = &[
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
pub(super) const SOCK_OPS_FIELDS: &[CtxField] = &[
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
pub(super) const BPF_SOCK_FIELDS: &[CtxField] = &[
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
pub(super) const SK_MSG_MD_FIELDS: &[CtxField] = &[
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
pub(super) const PT_REGS_FIELDS: &[CtxField] = &[
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
pub(super) const TRACE_ITER_TASK_FIELDS: &[CtxField] = &[
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
pub(super) const TP_BTF_MAYBE_NULL_ARGS: &[(&str, u8)] = &[
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

pub(super) fn tp_btf_arg_is_maybe_null(tp_target: &str, arg_idx: u8) -> bool {
    TP_BTF_MAYBE_NULL_ARGS
        .iter()
        .any(|(tp, idx)| *tp == tp_target && *idx == arg_idx)
}
