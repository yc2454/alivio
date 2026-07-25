#![allow(dead_code)]

// src/analysis/mem_region_model.rs
//
// Data-driven BPF memory region field definitions and access validation.
//
// This module defines the layout of kernel objects reachable via pointers
// obtained from context fields or helper return values (e.g., struct bpf_sock,
// struct bpf_tcp_sock). These are distinct from context structs (sk_buff, xdp_md)
// which are the program's first argument.
//
// Key differences from context access:
// - Pointers to mem regions can be NULL (must be null-checked before dereference)
// - All fields are read-only (no writes permitted)
// - No program-type-specific overrides
// - No kernel rewriting of access offsets
// - No scratch regions

use crate::{analysis::machine::reg_types::RegType, ast::MemSize};

// ===========================================================================
// Core Types
// ===========================================================================

#[derive(Clone, Copy, Debug)]
pub enum MemFieldKind {
    /// Scalar value (int, flags, etc.)
    Scalar,
    /// Scalar to another BTF struct
    BtfPtr {
        type_name: &'static str,
        nullable: bool,
    },
}

/// A field in a BPF memory region struct.
#[derive(Clone, Copy, Debug)]
pub struct MemRegionField {
    /// Byte offset from pointer base
    pub offset: i16,
    /// Field size
    pub size: MemSize,
    /// Allow sub-field (1, 2-byte) aligned reads within the field
    pub narrow_access: bool,
    pub kind: MemFieldKind,
}

/// Result of validating a memory region access.
#[derive(Clone, Copy, Debug)]
pub struct MemRegionAccessInfo {
    /// Whether this field can be read
    pub readable: bool,
}

// ===========================================================================
// Field Tables
// ===========================================================================

/// struct bpf_sock
///
/// Reference: linux/include/uapi/linux/bpf.h
///
/// Returned by:
///   - __sk_buff->sk (offset 168)
///   - bpf_sk_lookup->sk (offset 0)
///   - bpf_sk_fullsock() helper
///   - bpf_get_listener_sock() helper
///
/// struct bpf_sock {
///     __u32 bound_dev_if;       // 0
///     __u32 family;             // 4
///     __u32 type;               // 8
///     __u32 protocol;           // 12
///     __u32 mark;               // 16
///     __u32 priority;           // 20
///     __u32 src_ip4;            // 24
///     __u32 src_ip6[4];         // 28-43
///     __u32 src_port;           // 44
///     __u32 dst_port;           // 48 (stored in network byte order in first 16 bits)
///     __u32 dst_ip4;            // 52
///     __u32 dst_ip6[4];         // 56-71
///     __u32 state;              // 72
///     __s32 rx_queue_mapping;   // 76
/// };
const BPF_SOCK_FIELDS: &[MemRegionField] = &[
    // __u32 bound_dev_if
    MemRegionField {
        offset: 0,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 family
    MemRegionField {
        offset: 4,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 type
    MemRegionField {
        offset: 8,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 protocol
    MemRegionField {
        offset: 12,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 mark
    MemRegionField {
        offset: 16,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 priority
    MemRegionField {
        offset: 20,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 src_ip4
    MemRegionField {
        offset: 24,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 src_ip6[4]
    MemRegionField {
        offset: 28,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    MemRegionField {
        offset: 32,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    MemRegionField {
        offset: 36,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    MemRegionField {
        offset: 40,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 src_port
    MemRegionField {
        offset: 44,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 dst_port
    MemRegionField {
        offset: 48,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 dst_ip4
    MemRegionField {
        offset: 52,
        size: MemSize::U32,
        narrow_access: false,
        kind: MemFieldKind::Scalar,
    },
    // __u32 dst_ip6[4]
    MemRegionField {
        offset: 56,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    MemRegionField {
        offset: 60,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    MemRegionField {
        offset: 64,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    MemRegionField {
        offset: 68,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 state
    MemRegionField {
        offset: 72,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __s32 rx_queue_mapping
    MemRegionField {
        offset: 76,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
];

/// `bpf_sock_common_is_valid_access`: the subset of `bpf_sock` fields
/// that map to `struct sock_common` (the embedded base shared by every
/// sock subtype). Loadable through PTR_TO_SOCK_COMMON without first
/// promoting via `bpf_sk_fullsock(sk)`.
///
/// What's IN: family, src/dst IPs, src/dst ports, state — all backed
/// by `skc_*` fields in `struct sock_common`.
///
/// What's OUT (fullsock-only — kernel rejects with "invalid sock_common
/// access" per `verifier_sock.c::sk_sk_type_fullsock_field_1`):
/// bound_dev_if (0), type (8), protocol (12), mark (16), priority (20),
/// rx_queue_mapping (76).
const BPF_SOCK_COMMON_FIELDS: &[MemRegionField] = &[
    // family @ 4
    MemRegionField {
        offset: 4,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // src_ip4 @ 24
    MemRegionField {
        offset: 24,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // src_ip6[4] @ 28..44
    MemRegionField {
        offset: 28,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    MemRegionField {
        offset: 32,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    MemRegionField {
        offset: 36,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    MemRegionField {
        offset: 40,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // src_port @ 44
    MemRegionField {
        offset: 44,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // dst_port @ 48 (BPF accepts U32 *and* U16 for compat — handled by narrow_access)
    MemRegionField {
        offset: 48,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // dst_ip4 @ 52
    MemRegionField {
        offset: 52,
        size: MemSize::U32,
        narrow_access: false,
        kind: MemFieldKind::Scalar,
    },
    // dst_ip6[4] @ 56..72
    MemRegionField {
        offset: 56,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    MemRegionField {
        offset: 60,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    MemRegionField {
        offset: 64,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    MemRegionField {
        offset: 68,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // state @ 72
    MemRegionField {
        offset: 72,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
];

/// struct bpf_tcp_sock
///
/// Reference: linux/include/uapi/linux/bpf.h
///
/// Returned by:
///   - bpf_tcp_sock() helper
///   - bpf_skc_to_tcp_sock() helper
///
/// struct bpf_tcp_sock {
///     __u32 snd_cwnd;           // 0
///     __u32 srtt_us;            // 4
///     __u32 rtt_min;            // 8
///     __u32 snd_ssthresh;       // 12
///     __u32 rcv_nxt;            // 16
///     __u32 snd_nxt;            // 20
///     __u32 snd_una;            // 24
///     __u32 mss_cache;          // 28
///     __u32 ecn_flags;          // 32
///     __u32 rate_delivered;     // 36
///     __u32 rate_interval_us;   // 40
///     __u32 packets_out;        // 44
///     __u32 retrans_out;        // 48
///     __u32 total_retrans;      // 52
///     __u32 segs_in;            // 56
///     __u32 data_segs_in;       // 60
///     __u32 segs_out;           // 64
///     __u32 data_segs_out;      // 68
///     __u32 lost_out;           // 72
///     __u32 sacked_out;         // 76
///     __u64 bytes_received;     // 80
///     __u64 bytes_acked;        // 88
///     __u32 dsack_dups;         // 96
///     __u32 delivered;          // 100
///     __u32 delivered_ce;       // 104
///     __u32 icsk_retransmits;   // 108
/// };
const BPF_TCP_SOCK_FIELDS: &[MemRegionField] = &[
    // __u32 snd_cwnd
    MemRegionField {
        offset: 0,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 srtt_us
    MemRegionField {
        offset: 4,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 rtt_min
    MemRegionField {
        offset: 8,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 snd_ssthresh
    MemRegionField {
        offset: 12,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 rcv_nxt
    MemRegionField {
        offset: 16,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 snd_nxt
    MemRegionField {
        offset: 20,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 snd_una
    MemRegionField {
        offset: 24,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 mss_cache
    MemRegionField {
        offset: 28,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 ecn_flags
    MemRegionField {
        offset: 32,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 rate_delivered
    MemRegionField {
        offset: 36,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 rate_interval_us
    MemRegionField {
        offset: 40,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 packets_out
    MemRegionField {
        offset: 44,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 retrans_out
    MemRegionField {
        offset: 48,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 total_retrans
    MemRegionField {
        offset: 52,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 segs_in
    MemRegionField {
        offset: 56,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 data_segs_in
    MemRegionField {
        offset: 60,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 segs_out
    MemRegionField {
        offset: 64,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 data_segs_out
    MemRegionField {
        offset: 68,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 lost_out
    MemRegionField {
        offset: 72,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 sacked_out
    MemRegionField {
        offset: 76,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u64 bytes_received
    MemRegionField {
        offset: 80,
        size: MemSize::U64,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u64 bytes_acked
    MemRegionField {
        offset: 88,
        size: MemSize::U64,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 dsack_dups
    MemRegionField {
        offset: 96,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 delivered
    MemRegionField {
        offset: 100,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 delivered_ce
    MemRegionField {
        offset: 104,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 icsk_retransmits
    MemRegionField {
        offset: 108,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
];

/// struct bpf_xfrm_state
///
/// Reference: linux/include/uapi/linux/bpf.h
///
/// Returned by:
///   - bpf_skb_get_xfrm_state() helper
///
/// struct bpf_xfrm_state {
///     __u32 reqid;              // 0
///     __u32 spi;                // 4
///     __u16 family;             // 8
///     __u16 ext;                // 10 (padding)
///     union {
///         __u32 remote_ipv4;    // 12
///         __u32 remote_ipv6[4]; // 12-27
///     };
/// };
const BPF_XFRM_STATE_FIELDS: &[MemRegionField] = &[
    // __u32 reqid
    MemRegionField {
        offset: 0,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 spi
    MemRegionField {
        offset: 4,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u16 family
    MemRegionField {
        offset: 8,
        size: MemSize::U16,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 remote_ipv4 / remote_ipv6[0]
    MemRegionField {
        offset: 12,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 remote_ipv6[1]
    MemRegionField {
        offset: 16,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 remote_ipv6[2]
    MemRegionField {
        offset: 20,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // __u32 remote_ipv6[3]
    MemRegionField {
        offset: 24,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
];

/// struct bpf_iter_meta
///
/// Reference: kernel/bpf/bpf_iter.c
///
/// struct bpf_iter_meta {
///     struct seq_file *seq;   // 0
///     u64 session_id;         // 8
///     u64 seq_num;            // 16
/// };
const BPF_ITER_META_FIELDS: &[MemRegionField] = &[
    // struct seq_file *seq
    MemRegionField {
        offset: 0,
        size: MemSize::U64,
        narrow_access: false,
        kind: MemFieldKind::BtfPtr {
            type_name: "seq_file",
            nullable: false,
        },
    },
    // u64 session_id
    MemRegionField {
        offset: 8,
        size: MemSize::U64,
        narrow_access: false,
        kind: MemFieldKind::Scalar,
    },
    // u64 seq_num
    MemRegionField {
        offset: 16,
        size: MemSize::U64,
        narrow_access: false,
        kind: MemFieldKind::Scalar,
    },
];

/// struct bpf_map
///
/// Reference: linux/include/linux/bpf.h
///
/// Obtained via BPF_LD_MAP_FD instruction (PTR_TO_MAP_PTR).
/// Direct access requires CAP_PERFMON or CAP_SYS_ADMIN.
///
/// struct bpf_map {
///     const struct bpf_map_ops *ops;    // 0
///     struct bpf_map *inner_map_meta;   // 8
///     void *security;                   // 16 (if CONFIG_SECURITY)
///     enum bpf_map_type map_type;       // 24
///     u32 key_size;                     // 28
///     u32 value_size;                   // 32
///     u32 max_entries;                  // 36
///     u64 map_flags;                    // 40
///     u32 id;                           // 48
///     u32 numa_node;                    // 52
///     u32 btf_key_type_id;              // 56
///     u32 btf_value_type_id;            // 60
///     u32 btf_vmlinux_value_type_id;    // 64
///     struct btf *btf;                  // 72
/// };
const BPF_MAP_FIELDS: &[MemRegionField] = &[
    // const struct bpf_map_ops *ops
    MemRegionField {
        offset: 0,
        size: MemSize::U64,
        narrow_access: false,
        kind: MemFieldKind::Scalar,
    },
    // struct bpf_map *inner_map_meta
    MemRegionField {
        offset: 8,
        size: MemSize::U64,
        narrow_access: false,
        kind: MemFieldKind::Scalar,
    },
    // void *security (CONFIG_SECURITY)
    MemRegionField {
        offset: 16,
        size: MemSize::U64,
        narrow_access: false,
        kind: MemFieldKind::Scalar,
    },
    // enum bpf_map_type map_type
    MemRegionField {
        offset: 24,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // u32 key_size
    MemRegionField {
        offset: 28,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // u32 value_size
    MemRegionField {
        offset: 32,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // u32 max_entries
    MemRegionField {
        offset: 36,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // u64 map_flags
    MemRegionField {
        offset: 40,
        size: MemSize::U64,
        narrow_access: false,
        kind: MemFieldKind::Scalar,
    },
    // u32 id
    MemRegionField {
        offset: 48,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // u32 numa_node
    MemRegionField {
        offset: 52,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // u32 btf_key_type_id
    MemRegionField {
        offset: 56,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // u32 btf_value_type_id
    MemRegionField {
        offset: 60,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // u32 btf_vmlinux_value_type_id
    MemRegionField {
        offset: 64,
        size: MemSize::U32,
        narrow_access: true,
        kind: MemFieldKind::Scalar,
    },
    // (4 bytes padding for alignment)
    // struct btf *btf
    MemRegionField {
        offset: 72,
        size: MemSize::U64,
        narrow_access: false,
        kind: MemFieldKind::Scalar,
    },
];

// ===========================================================================
// Field Lookup
// ===========================================================================

/// Look up field info for a memory region access.
/// Returns None if no valid field exists at (offset, size).
fn lookup_field(
    reg_type: RegType,
    fields: &[MemRegionField],
    off: i16,
    size: i64,
) -> Option<MemRegionAccessInfo> {
    let access_end = off + size as i16;

    // Check natural alignment
    if off % size as i16 != 0 {
        return None;
    }

    fields
        .iter()
        .find(|f| {
            if f.narrow_access {
                if size == 1 {
                    // Cannot access bpf_sock offset 50-51
                    return !(matches!(
                        reg_type,
                        RegType::PtrToSockCommon { .. } | RegType::PtrToSocket { .. }
                    ) && off == 50);
                }
                // Allow aligned sub-field access within bounds
                let field_end = f.offset + f.size.bytes() as i16;
                off == f.offset && access_end <= field_end
            } else {
                // Require exact offset and size match
                f.offset == off && f.size.bytes() == size as usize
            }
        })
        .map(|_| MemRegionAccessInfo { readable: true })
}

/// Get the field table for a given memory region.
fn get_region_fields(reg_type: RegType) -> Option<&'static [MemRegionField]> {
    match reg_type {
        RegType::PtrToSockCommon { .. } => Some(BPF_SOCK_COMMON_FIELDS),
        RegType::PtrToTcpSock { .. } => Some(BPF_TCP_SOCK_FIELDS),
        RegType::PtrToSocket { .. } => Some(BPF_SOCK_FIELDS),
        RegType::PtrToBtfId {
            type_name: "bpf_iter_meta",
            ..
        } => Some(BPF_ITER_META_FIELDS),
        RegType::PtrToMapObject { .. } => Some(BPF_MAP_FIELDS),
        _ => None,
    }
}

// ===========================================================================
// Public API
// ===========================================================================

/// Validate a memory region access and return access info if valid.
///
/// Returns:
/// - `Some(info)` if the access is a valid read
/// - `None` if the access is invalid (wrong offset, wrong size, or unknown region)
///
/// All memory region accesses are read-only. Writes are never permitted.
pub fn validate_mem_region_access(
    reg_type: RegType,
    off: i16,
    size: i64,
) -> Option<MemRegionAccessInfo> {
    let fields = get_region_fields(reg_type)?;
    lookup_field(reg_type, fields, off, size)
}

/// Check if a memory region field is readable at the given offset and size.
///
/// Convenience wrapper around `validate_mem_region_access`.
pub fn is_valid_mem_region_read(reg_type: RegType, off: i16, size: i64) -> bool {
    validate_mem_region_access(reg_type, off, size)
        .map(|info| info.readable)
        .unwrap_or(false)
}
