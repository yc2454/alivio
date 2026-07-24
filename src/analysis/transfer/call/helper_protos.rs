// src/analysis/transfer/call/helper_protos.rs
//
// Helper-function proto table (`get_helper_proto`) and small per-helper
// utility predicates (`is_fastcall_helper`, etc.).

use crate::common::constants;
use crate::parsing::btf::SpecialFieldKind;
use super::kfunc_protos::get_kfunc_proto;
use super::signatures::{ArgKind::*, CallFlags, CallProto, RetKind, SideEffect};
use super::signatures::pairs;

pub fn get_helper_proto(helper: u32) -> Option<CallProto> {
    Some(match helper {
        // ---- Map operations ----
        constants::BPF_MAP_LOOKUP_ELEM => CallProto::with_args([
            ConstMapPtr, // R1: map
            PtrToMapKey, // R2: key
            DontCare,
            DontCare,
            DontCare,
        ]),

        // bpf_map_lookup_percpu_elem(map, key, cpu) — same shape as
        // map_lookup_elem with an extra cpu scalar arg. Returns a
        // pointer to the per-cpu copy of the value, or NULL.
        // R0 typing handled by `update_call_types` (PtrToMapValueOrNull
        // keyed off R1's map).
        constants::BPF_MAP_LOOKUP_PERCPU_ELEM => CallProto::with_args([
            ConstMapPtr, // R1: map
            PtrToMapKey, // R2: key
            Anything,    // R3: cpu
            DontCare,
            DontCare,
        ]),

        constants::BPF_MAP_UPDATE_ELEM => CallProto::with_args([
            ConstMapPtr,   // R1: map
            PtrToMapKey,   // R2: key
            PtrToMapValue, // R3: value
            Anything,      // R4: flags
            DontCare,
        ]),

        constants::BPF_MAP_DELETE_ELEM => CallProto::with_args([
            ConstMapPtr, // R1: map
            PtrToMapKey, // R2: key
            DontCare,
            DontCare,
            DontCare,
        ]),

        constants::BPF_GET_LOCAL_STORAGE => CallProto::with_args([
            ConstMapPtr, // R1: map
            Anything,    // R2: index
            DontCare,
            DontCare,
            DontCare,
        ]),

        // ---- Memory helpers ----
        constants::BPF_GET_STACK => CallProto::with_args([
            PtrToCtx,
            PtrToUninitMem,
            ConstSizeOrZero,
            Anything,
            DontCare,
        ])
        .mem_size_pairs(&pairs::GET_STACK),

        // ---- Tail call ----
        constants::BPF_TAIL_CALL => CallProto::with_args([
            PtrToCtx,    // R1: ctx
            ConstMapPtr, // R2: prog_array_map
            Anything,    // R3: index
            DontCare,
            DontCare,
        ]),

        // ---- Socket/context helpers ----
        constants::BPF_GET_SOCKET_COOKIE => CallProto::with_args([
            // Kernel registers 4 per-prog-type protos for this helper
            // (skb-ctx / sock / sock_addr-ctx / sock_common-btf-id).
            // We use PtrToCtx for the validator entry point; the
            // sock-shaped variants are admitted via a per-helper
            // relaxation in `validate_ptr_to_ctx` (keyed on
            // `ctx.helper == BPF_GET_SOCKET_COOKIE`) so that ctx-offset
            // validation still fires for skb-ctx programs.
            PtrToCtx, // R1: ctx / sock / btf_id sock_common
            DontCare, DontCare, DontCare, DontCare,
        ]),

        constants::BPF_GET_NETNS_COOKIE => CallProto::with_args([
            PtrToCtxOrNull, // R1: ctx (nullable — kernel accepts NULL)
            DontCare, DontCare, DontCare, DontCare,
        ]),

        constants::BPF_CSUM_UPDATE => CallProto::with_args([
            PtrToCtx, // R1: skb
            DontCare, DontCare, DontCare, DontCare,
        ]),

        constants::BPF_CSUM_DIFF => CallProto::with_args([
            PtrToMemOrNull,  // R1: from
            ConstSizeOrZero, // R2: from_size
            PtrToMemOrNull,  // R3: to
            ConstSizeOrZero, // R4: to_size
            Anything,        // R5: seed
        ])
        .mem_size_pairs(&pairs::CSUM_DIFF),

        constants::BPF_SKB_ECN_SET_CE => CallProto::with_args([
            PtrToCtxOrNull, // R1: skb (can be NULL)
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ]),

        constants::BPF_GET_HASH_RECALC => CallProto::with_args([
            PtrToCtx, // R1: ctx
            DontCare, DontCare, DontCare, DontCare,
        ]),

        // ---- SKB data access ----
        constants::BPF_SKB_LOAD_BYTES => CallProto::with_args([
            PtrToCtx,       // R1: skb
            Anything,       // R2: offset
            PtrToUninitMem, // R3: to (destination buffer)
            ConstSize,      // R4: len
            DontCare,
        ])
        .mem_size_pairs(&pairs::SKB_LOAD_BYTES),

        constants::BPF_SKB_VLAN_PUSH => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: vlan_proto
            Anything, // R3: vlan_tci
            DontCare, DontCare,
        ]),

        constants::BPF_SKB_GET_TUNNEL_KEY => CallProto::with_args([
            PtrToCtx,       // R1: skb
            PtrToUninitMem, // R2: key (buffer to store key)
            ConstSize,      // R3: size
            Anything,       // R4: flags
            DontCare,
        ])
        .mem_size_pairs(&pairs::SKB_GET_TUNNEL_KEY),

        constants::BPF_SKB_SET_TUNNEL_KEY => CallProto::with_args([
            PtrToCtx,  // R1: skb
            PtrToMem,  // R2: key
            ConstSize, // R3: size
            Anything,  // R4: flags
            DontCare,
        ])
        .mem_size_pairs(&pairs::SKB_SET_TUNNEL_KEY),

        constants::BPF_SKB_VLAN_POP => CallProto::with_args([
            PtrToCtx, // R1: skb
            DontCare, DontCare, DontCare, DontCare,
        ]),

        constants::BPF_SKB_STORE_BYTES => CallProto::with_args([
            PtrToCtx,  // R1: skb
            Anything,  // R2: offset
            PtrToMem,  // R3: from (source buffer)
            ConstSize, // R4: len
            DontCare,
        ])
        .mem_size_pairs(&pairs::SKB_STORE_BYTES),

        // ---- skb-modifying helpers (real kernel SCHED_CLS/ACT
        // helpers; ctx + scalar args, RET_INTEGER). Faithful protos:
        // R1=ctx, remaining = scalars. Packet-pointer invalidation is
        // modeled by id in helper_invalidates_packets() — independent
        // of this proto. Mirrors the existing skb_store_bytes /
        // vlan_push idiom (RET_INTEGER → default per-helper R0). ----
        constants::BPF_SKB_CHANGE_PROTO => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: proto
            Anything, // R3: flags
            DontCare, DontCare,
        ]),

        constants::BPF_SKB_CHANGE_TYPE => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: type
            DontCare, DontCare, DontCare,
        ]),

        constants::BPF_SKB_PULL_DATA => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: len
            DontCare, DontCare, DontCare,
        ]),

        constants::BPF_SKB_CHANGE_HEAD => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: head_room
            Anything, // R3: flags
            DontCare, DontCare,
        ]),

        constants::BPF_SKB_ADJUST_ROOM => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: len_diff
            Anything, // R3: mode
            Anything, // R4: flags
            DontCare,
        ]),

        // bpf_sk_assign(skb, sk, flags): R2 = ARG_PTR_TO_BTF_ID_SOCK_COMMON.
        constants::BPF_SK_ASSIGN => CallProto::with_args([
            PtrToCtx,             // R1: skb
            PtrToBTFIdSockCommon, // R2: sk
            Anything,             // R3: flags
            DontCare, DontCare,
        ]),

        // bpf_get_current_task() -> u64 (RET_INTEGER, no args). Real
        // kernel helper id 35 (distinct from *_TASK_BTF 158).
        constants::BPF_GET_CURRENT_TASK => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
        }

        // ---- Redirect ----
        constants::BPF_REDIRECT => CallProto::with_args([
            Anything, // R1: ifindex
            Anything, // R2: flags
            DontCare, DontCare, DontCare,
        ]),

        // bpf_redirect_peer(ifindex, flags) -> int. Real SCHED_CLS/ACT
        // helper (id 155); same shape as bpf_redirect (both scalars, no
        // ctx, no packet modification → not in helper_invalidates_packets,
        // correctly).
        constants::BPF_REDIRECT_PEER => CallProto::with_args([
            Anything, // R1: ifindex
            Anything, // R2: flags
            DontCare, DontCare, DontCare,
        ]),

        // bpf_redirect_neigh(ifindex, params, plen, flags) -> int. Real
        // SCHED_CLS/ACT helper (id 152). Kernel proto (net/core/filter.c
        // bpf_redirect_neigh_proto): arg1=ARG_ANYTHING ifindex,
        // arg2=ARG_PTR_TO_MEM|PTR_MAYBE_NULL|MEM_RDONLY params,
        // arg3=ARG_CONST_SIZE_OR_ZERO plen, arg4=ARG_ANYTHING flags,
        // RET_INTEGER. The kernel returns this proto for SCHED_CLS.
        constants::BPF_REDIRECT_NEIGH => CallProto::with_args([
            Anything,             // R1: ifindex
            PtrToMemOrNull,       // R2: params (nullable, rdonly)
            ConstSizeOrZero,      // R3: plen
            Anything,             // R4: flags
            DontCare,
        ])
        .mem_size_pairs(&pairs::REDIRECT_NEIGH)
        .ret(RetKind::Scalar),

        // bpf_clone_redirect(skb, ifindex, flags) -> int. Real
        // SCHED_CLS/ACT helper (id 13): clones the skb and redirects
        // the clone. Kernel proto = [ARG_PTR_TO_CTX, ARG_ANYTHING,
        // ARG_ANYTHING], RET_INTEGER. In bpf_helper_changes_pkt_data
        // (net/core/filter.c) — invalidation handled by id in
        // helper_invalidates_packets (sound).
        constants::BPF_CLONE_REDIRECT => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: ifindex
            Anything, // R3: flags
            DontCare, DontCare,
        ]),

        // ---- XDP helpers ----
        constants::BPF_XDP_ADJUST_HEAD
        | constants::BPF_XDP_ADJUST_TAIL
        | constants::BPF_XDP_ADJUST_META => CallProto::with_args([
            PtrToCtx, // R1: xdp_md
            Anything, // R2: delta
            DontCare, DontCare, DontCare,
        ]),

        // ---- Tail modification ----
        constants::BPF_SKB_CHANGE_TAIL => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: len
            Anything, // R3: flags
            DontCare, DontCare,
        ]),

        // bpf_skb_set_tstamp(skb, tstamp, tstamp_type) -> long. TC helper
        // (test_tc_dtime). R1 is the skb ctx; the two value args are scalars.
        constants::BPF_SKB_SET_TSTAMP => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: tstamp (u64)
            Anything, // R3: tstamp_type (u32)
            DontCare, DontCare,
        ]),

        // ==== EXCEEDSMAXIMUMKNOWN backlog: previously-unmodeled helpers ====
        // These had no proto → get_helper_proto None → InvalidHelperId
        // ("exceeds maximum known helper ID") → load failure for the many
        // kernel-ACCEPTED selftests that call them. Faithful protos added
        // from the kernel uapi prototypes; mem+size args paired so the
        // helper-mem-access bounds check runs.

        // bpf_msg_redirect_hash(msg, map, key, flags) -> long.
        constants::BPF_MSG_REDIRECT_HASH => CallProto::with_args([
            PtrToCtx,    // R1: sk_msg
            ConstMapPtr, // R2: map
            PtrToMapKey, // R3: key
            Anything,    // R4: flags
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_sk_redirect_hash(skb, map, key, flags) -> long.
        constants::BPF_SK_REDIRECT_HASH => CallProto::with_args([
            PtrToCtx,    // R1: skb
            ConstMapPtr, // R2: map
            PtrToMapKey, // R3: key
            Anything,    // R4: flags
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_lwt_seg6_store_bytes(skb, offset, from, len) -> long.
        constants::BPF_LWT_SEG6_STORE_BYTES => CallProto::with_args([
            PtrToCtx,  // R1: skb
            Anything,  // R2: offset
            PtrToMem,  // R3: from
            ConstSize, // R4: len
            DontCare,
        ])
        .mem_size_pairs(&pairs::LWT_SEG6_STORE_BYTES),

        // bpf_rc_pointer_rel(ctx, rel_x, rel_y) -> long. lirc_mode2 helper.
        constants::BPF_RC_POINTER_REL => CallProto::with_args([
            PtrToCtx, // R1: ctx (sample)
            Anything, // R2: rel_x (s32)
            Anything, // R3: rel_y (s32)
            DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_tcp_check_syncookie(sk, iph, iph_len, th, th_len) -> long.
        constants::BPF_TCP_CHECK_SYNCOOKIE => CallProto::with_args([
            PtrToBTFIdSockCommon, // R1: sk
            PtrToMem,             // R2: iph
            ConstSize,            // R3: iph_len
            PtrToMem,             // R4: th
            ConstSize,            // R5: th_len
        ])
        .ret(RetKind::Scalar)
        .mem_size_pairs(&pairs::TCP_SYNCOOKIE),

        // bpf_tcp_gen_syncookie(sk, iph, iph_len, th, th_len) -> s64.
        constants::BPF_TCP_GEN_SYNCOOKIE => CallProto::with_args([
            PtrToBTFIdSockCommon, // R1: sk
            PtrToMem,             // R2: iph
            ConstSize,            // R3: iph_len
            PtrToMem,             // R4: th
            ConstSize,            // R5: th_len
        ])
        .ret(RetKind::Scalar)
        .mem_size_pairs(&pairs::TCP_SYNCOOKIE),

        // bpf_sysctl_get_current_value(ctx, buf, buf_len) -> long.
        constants::BPF_SYSCTL_GET_CURRENT_VALUE => CallProto::with_args([
            PtrToCtx,        // R1: bpf_sysctl ctx
            PtrToUninitMem,  // R2: buf (written)
            ConstSizeOrZero, // R3: buf_len
            DontCare, DontCare,
        ])
        .ret(RetKind::Scalar)
        .mem_size_pairs(&pairs::SYSCTL_GET_CURRENT_VALUE),

        // bpf_send_signal(sig) -> long.
        constants::BPF_SEND_SIGNAL => CallProto::with_args([
            Anything, // R1: sig
            DontCare, DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_sk_cgroup_id(sk) -> u64.
        constants::BPF_SK_CGROUP_ID => CallProto::with_args([
            PtrToBTFIdSockCommon, // R1: sk
            DontCare, DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_ringbuf_query(ringbuf, flags) -> u64.
        constants::BPF_RINGBUF_QUERY => CallProto::with_args([
            ConstMapPtr, // R1: ringbuf map
            Anything,    // R2: flags
            DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_store_hdr_opt(skops, from, len, flags) -> long.
        constants::BPF_STORE_HDR_OPT => CallProto::with_args([
            PtrToCtx,  // R1: bpf_sock_ops
            PtrToMem,  // R2: from
            ConstSize, // R3: len
            Anything,  // R4: flags
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .mem_size_pairs(&pairs::STORE_HDR_OPT),

        // bpf_get_func_arg(ctx, n, value) -> long. value is a u64* output.
        constants::BPF_GET_FUNC_ARG => CallProto::with_args([
            PtrToCtx,  // R1: tracing ctx
            Anything,  // R2: n
            PtrToLong, // R3: value (u64 out)
            DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_xdp_store_bytes(xdp, offset, buf, len) -> long.
        constants::BPF_XDP_STORE_BYTES => CallProto::with_args([
            PtrToCtx,  // R1: xdp_md
            Anything,  // R2: offset
            PtrToMem,  // R3: buf
            ConstSize, // R4: len
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .mem_size_pairs(&pairs::XDP_STORE_BYTES),

        // bpf_ima_file_hash(file, dst, size) -> long. file is a BTF ptr,
        // dst is a written buffer sized by `size`.
        constants::BPF_IMA_FILE_HASH => CallProto::with_args([
            PtrToBtfId,      // R1: struct file *
            PtrToUninitMem,  // R2: dst (written)
            ConstSizeOrZero, // R3: size
            DontCare, DontCare,
        ])
        .ret(RetKind::Scalar)
        .mem_size_pairs(&pairs::IMA_FILE_HASH),

        // bpf_sk_ancestor_cgroup_id(sk, ancestor_level) -> u64.
        constants::BPF_SK_ANCESTOR_CGROUP_ID => CallProto::with_args([
            PtrToBTFIdSockCommon, // R1: sk
            Anything,             // R2: ancestor_level
            DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_reserve_hdr_opt(skops, len, flags) -> long.
        constants::BPF_RESERVE_HDR_OPT => CallProto::with_args([
            PtrToCtx, // R1: bpf_sock_ops
            Anything, // R2: len
            Anything, // R3: flags
            DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_get_func_ret(ctx, value) -> long. value is a u64* output.
        constants::BPF_GET_FUNC_RET => CallProto::with_args([
            PtrToCtx,  // R1: tracing ctx
            PtrToLong, // R2: value (u64 out)
            DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- Socket lookup ----
        constants::BPF_SKC_LOOKUP_TCP => CallProto::with_args([
            PtrToCtx, // R1: ctx
            PtrToMem, // R2: tuple
            Anything, // R3: tuple_size
            DontCare, DontCare,
        ])
        .ret(RetKind::PtrToSockCommon)
        .flags(CallFlags::ACQUIRE.union(CallFlags::RET_NULL))
        .mem_size_pairs(&pairs::SK_LOOKUP_TCP),

        constants::BPF_SK_LOOKUP_TCP => CallProto::with_args([
            PtrToCtx,  // R1: ctx
            PtrToMem,  // R2: tuple
            ConstSize, // R3: tuple_size
            Anything,  // R4: netns
            Anything,  // R5: flags
        ])
        .ret(RetKind::PtrToSocket)
        .flags(CallFlags::ACQUIRE.union(CallFlags::RET_NULL))
        .mem_size_pairs(&pairs::SK_LOOKUP_TCP),

        constants::BPF_SK_LOOKUP_UDP => CallProto::with_args([
            PtrToCtx,  // R1: ctx
            PtrToMem,  // R2: tuple
            ConstSize, // R3: tuple_size
            Anything,  // R4: netns
            Anything,  // R5: flags
        ])
        .ret(RetKind::PtrToSocket)
        .flags(CallFlags::ACQUIRE.union(CallFlags::RET_NULL))
        .mem_size_pairs(&pairs::SK_LOOKUP_UDP),

        constants::BPF_SK_RELEASE => CallProto::with_args([
            PtrToSocket, // R1: socket
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .flags(CallFlags::RELEASE)
        .side_effects(&[SideEffect::ReleaseRefFromArg { arg: 0 }]),

        constants::BPF_SKC_TO_UDP6_SOCK => CallProto::with_args([
            PtrToSocket, // R1: socket
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ]),

        constants::BPF_SK_FULLSOCK => CallProto::with_args([
            PtrToSockCommon, // R1: sock_common
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ]),

        constants::BPF_TCP_SOCK => {
            CallProto::with_args([PtrToSockCommon, DontCare, DontCare, DontCare, DontCare])
        }

        // ---- Socket storage helpers ----
        constants::BPF_SK_STORAGE_GET => CallProto::with_args([
            ConstMapPtr,
            PtrToBTFIdSockCommon,
            PtrToMapValueOrNull,
            Anything,
            DontCare,
        ]),

        constants::BPF_GET_SOCKOPT => {
            // R1 is `bpf_socket` (kernel UAPI). The kernel verifier accepts
            // it as PtrToCtx in cgroup_sock_addr/sock_ops contexts AND as
            // a trusted PtrToBtfId{sock} in struct_ops contexts (where the
            // BPF_PROG-wrapped struct_ops method has unpacked the sock arg
            // out of the ctx array). Modeling as `Anything` matches the
            // multi-shape acceptance and lets struct_ops methods like
            // bpf_dctcp_init pass; the size pair on (R4, R5) still gates
            // the actual write region.
            CallProto::with_args([Anything, Anything, Anything, PtrToUninitMem, ConstSize])
                .mem_size_pairs(&pairs::GET_SOCKOPT)
        }

        // ---- FIB lookup ----
        constants::BPF_FIB_LOOKUP => CallProto::with_args([
            PtrToCtx, // R1: ctx
            PtrToMem, // R2: params (bpf_fib_lookup struct)
            Anything, // R3: plen
            Anything, // R4: flags
            DontCare,
        ]),

        constants::BPF_PROBE_READ
        | constants::BPF_PROBE_READ_STR
        | constants::BPF_PROBE_READ_USER => CallProto::with_args([
            PtrToUninitMem,  // R1: dst
            ConstSizeOrZero, // R2: size
            Anything,        // R3: unsafe_ptr (user address)
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::PROBE_READ),

        constants::BPF_PROBE_READ_KERNEL => CallProto::with_args([
            PtrToUninitMem,  // R1: dst (output buffer)
            ConstSizeOrZero, // R2: size
            Anything,        // R3: unsafe_ptr (kernel address, not validated)
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::PROBE_READ),

        constants::BPF_PERF_EVENT_READ_VALUE => CallProto::with_args([
            ConstMapPtr,     // R1: map
            Anything,        // R2: flags
            PtrToUninitMem,  // R3: buf
            ConstSizeOrZero, // R4: buf_size
            DontCare,
        ])
        .mem_size_pairs(&pairs::PERF_EVENT_READ_VALUE),

        constants::BPF_PERF_PROG_READ_VALUE => CallProto::with_args([
            PtrToCtx,        // R1: ctx
            PtrToUninitMem,  // R2: buf
            ConstSizeOrZero, // R3: buf_size
            DontCare,        // R4: flags (not verified here)
            DontCare,
        ])
        .mem_size_pairs(&pairs::PERF_PROG_READ_VALUE),

        // ---- Spin lock ----
        // void bpf_spin_lock(struct bpf_spin_lock *lock)
        // void bpf_spin_unlock(struct bpf_spin_lock *lock)
        // R1 must be a PtrToMapValue aimed at a `bpf_spin_lock` field
        // recorded in the map's value-type BTF. The shape check rides
        // `MapValueSpecial { SpinLock }`; the lock-state mutation
        // (`active_lock` acquire / release) is driven by the
        // `SPIN_LOCK_{ACQUIRE,RELEASE}` flags in the pre-call hook.
        constants::BPF_SPIN_LOCK => CallProto::with_args([
            MapValueSpecial { kind: SpecialFieldKind::SpinLock },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .flags(CallFlags::SPIN_LOCK_ACQUIRE),

        constants::BPF_SPIN_UNLOCK => CallProto::with_args([
            MapValueSpecial { kind: SpecialFieldKind::SpinLock },
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar)
        .flags(CallFlags::SPIN_LOCK_RELEASE),

        // ---- RCU read-side critical section ----
        // void bpf_rcu_read_lock(void)
        // void bpf_rcu_read_unlock(void)
        constants::BPF_RCU_READ_LOCK => CallProto::with_args([
            DontCare, DontCare, DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar)
        .flags(CallFlags::RCU_READ_LOCK),

        constants::BPF_RCU_READ_UNLOCK => CallProto::with_args([
            DontCare, DontCare, DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar)
        .flags(CallFlags::RCU_READ_UNLOCK),

        // ---- Timers ----
        // long bpf_timer_init(struct bpf_timer *timer, struct bpf_map *map, u64 flags)
        constants::BPF_TIMER_INIT => CallProto::with_args([
            MapValueSpecial { kind: SpecialFieldKind::Timer }, // R1: &timer field
            ConstMapPtr,                                       // R2: map the cb will operate on
            Anything,                                          // R3: flags
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // long bpf_timer_set_callback(struct bpf_timer *timer,
        //                             void *callback_fn)
        // Routed through is_callback_helper → transfer_callback_helper for
        // the cb-frame fork; this proto just covers the arg validation
        // (timer field + PtrToCallback) and post-call R0 typing for the
        // skip successor (the cb-frame branch updates R0 separately).
        constants::BPF_TIMER_SET_CALLBACK => CallProto::with_args([
            MapValueSpecial { kind: SpecialFieldKind::Timer }, // R1: &timer field
            PtrToCallback,                                     // R2: callback subprog
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // long bpf_timer_start(struct bpf_timer *timer, u64 nsecs, u64 flags)
        constants::BPF_TIMER_START => CallProto::with_args([
            MapValueSpecial { kind: SpecialFieldKind::Timer }, // R1: &timer field
            Anything,                                          // R2: nsecs
            Anything,                                          // R3: flags
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // long bpf_timer_cancel(struct bpf_timer *timer)
        constants::BPF_TIMER_CANCEL => CallProto::with_args([
            MapValueSpecial { kind: SpecialFieldKind::Timer }, // R1: &timer field
            DontCare,
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- Ringbuf helpers ----
        constants::BPF_RINGBUF_OUTPUT => CallProto::with_args([
            ConstMapPtr,     // R1: ringbuf map
            PtrToMem,        // R2: data to copy (must be initialized)
            ConstSizeOrZero, // R3: size
            Anything,        // R4: flags
            DontCare,
        ]),

        constants::BPF_RINGBUF_RESERVE => CallProto::with_args([
            ConstMapPtr,
            ConstAllocSizeOrZero,
            Anything,
            DontCare,
            DontCare,
        ]),

        constants::BPF_RINGBUF_SUBMIT => {
            CallProto::with_args([PtrToAllocMem, Anything, DontCare, DontCare, DontCare])
        }

        // bpf_user_ringbuf_drain(map, callback, ctx, flags)
        // Drains a user-space-written ringbuf, invoking `callback`
        // for each sample. Routed through `is_callback_helper` →
        // `transfer_callback_helper` so the callback subprog gets a
        // pushed frame on the enter-callback successor; the callback
        // signature is `(struct bpf_dynptr *dynptr, void *ctx) -> long`,
        // but per the existing callback convention we leave R1/R2 as
        // NotInit in the callee frame — programs that dereference
        // `ctx` (R2) without typing reject, which is the right outcome
        // for the lone existing test (`unsafe_ringbuf_drain`).
        constants::BPF_USER_RINGBUF_DRAIN => CallProto::with_args([
            ConstMapPtrOfType(crate::common::constants::BPF_MAP_TYPE_USER_RINGBUF),
            PtrToCallback,
            Anything,
            Anything,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_for_each_map_elem(map, callback_fn, callback_ctx, flags)
        // -> long. Real kernel helper id 164, mirrors
        // `bpf_for_each_map_elem_proto` (ARG_CONST_MAP_PTR,
        // ARG_PTR_TO_FUNC, ARG_PTR_TO_STACK_OR_NULL, ARG_ANYTHING).
        // Already wired in is_callback_helper / callback_arg_reg(R2);
        // only the proto was missing, so the unknown-helper backstop
        // rejected it → 7 false rejects (`tail_mcast_ep_delivery`,
        // overlay, all clang variants — kernel ACCEPTS per the
        // per-program oracle). callback_ctx as `Anything` matches the
        // sibling USER_RINGBUF_DRAIN convention.
        constants::BPF_FOR_EACH_MAP_ELEM => CallProto::with_args([
            ConstMapPtr,   // R1: map
            PtrToCallback, // R2: callback_fn
            Anything,      // R3: callback_ctx (stack-or-null)
            Anything,      // R4: flags
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- Information helpers ----
        constants::BPF_KTIME_GET_NS => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
        }
        constants::BPF_KTIME_GET_COARSE_NS => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
        }

        // ---- Process info helpers ----

        // bpf_get_current_pid_tgid() -> u64 (no args). Real kernel
        // helper (BPF_FUNC id 14) that was previously unregistered, so
        // validate_helper_args skipped it. Registering it is the
        // faithful model (no pointer args to validate, scalar return)
        // and is the prerequisite for the unknown-helper-REJECT
        // backstop: test_get_stack_rawtp (a real bundle-producer) calls
        // this helper, so without a proto the backstop would
        // false-reject it.
        constants::BPF_GET_CURRENT_PID_TGID => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
        }

        constants::BPF_GET_TASK_STACK => CallProto::with_args([
            PtrToBtfId,
            PtrToUninitMem,
            ConstSizeOrZero,
            Anything,
            DontCare,
        ])
        .mem_size_pairs(&pairs::GET_TASK_STACK),

        // bpf_get_branch_snapshot(void *entries, u32 size, u64 flags) -> long
        // Writes ≤ size bytes; R0 ∈ [-MAX_ERRNO, R2_max]. The size-arg
        // bound on R0 is what unblocks `total_entries / 24 ≤ ENTRY_CNT`
        // for static reasoning over `entries[i]` arrays — without it,
        // total_entries is unbounded and the `i < total_entries` exit
        // branch can't refine i's bound.
        constants::BPF_GET_BRANCH_SNAPSHOT => CallProto::with_args([
            PtrToUninitMem,
            ConstSize,
            Anything,
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::GET_BRANCH_SNAPSHOT)
        .ret(RetKind::Scalar),

        // ---- Sockmap operations ----
        constants::BPF_SOCK_MAP_UPDATE => CallProto::with_args([
            PtrToCtx,    // R1: bpf_sock_ops context (SockOps only)
            ConstMapPtr, // R2: sockmap
            PtrToMapKey, // R3: key
            Anything,    // R4: flags
            DontCare,
        ]),

        // ---- Miscellaneous ----
        constants::BPF_GET_PRANDOM_U32 => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
        }

        constants::BPF_TRACE_PRINTK => CallProto::with_args([
            PtrToMem,  // R1: fmt string
            ConstSize, // R2: fmt_size (MUST BE > 0)
            // R3-R5: the printk varargs are NOT proto args — kernel
            // bpf_trace_printk_proto (kernel/trace/bpf_trace.c:386-392)
            // declares only arg1/arg2; arg3-5 stay ARG_DONTCARE, so
            // get_call_summary num_params=2 and compute_insn_live_regs
            // (verifier.c:26141-26145, use=GENMASK(num_params,1)) kills
            // r3-r5 liveness at every printk call. Marking them Anything
            // would keep r3-r5 live and block regsafe-parity prune hits.
            DontCare,
            DontCare,
            DontCare,
        ])
        // Kernel bpf_trace_printk_proto: fmt/fmt_size ARE a checked
        // mem/size pair — the fmt bytes get bounds-checked and live-stack
        // READ-MARKED (see pairs::TRACE_PRINTK for the full story).
        .mem_size_pairs(&pairs::TRACE_PRINTK),

        // bpf_trace_vprintk(fmt, fmt_size, data, data_len) -> int. Real
        // helper (id 177), gpl_only. Kernel proto (kernel/trace/
        // bpf_trace.c bpf_trace_vprintk_proto): arg1=ARG_PTR_TO_MEM|
        // MEM_RDONLY fmt, arg2=ARG_CONST_SIZE fmt_size, arg3=ARG_PTR_TO_
        // MEM|PTR_MAYBE_NULL|MEM_RDONLY data, arg4=ARG_CONST_SIZE_OR_ZERO
        // data_len, RET_INTEGER. Returned from bpf_base_func_proto
        // (kernel/bpf/helpers.c) → available to ~all prog types, so the
        // prior "Invalid helper ID 177" reject was a zovia-only false
        // positive (≤-BCF preserved). fmt/fmt_size mirror bpf_trace_printk
        // (ConstSize-bounded, no explicit pair); data/data_len mirror the
        // nullable tail of bpf_snprintf.
        constants::BPF_TRACE_VPRINTK => CallProto::with_args([
            PtrToMem,        // R1: fmt string (rdonly)
            ConstSize,       // R2: fmt_size (MUST BE > 0)
            PtrToMemOrNull,  // R3: data (u64 array; may be NULL if len=0)
            ConstSizeOrZero, // R4: data_len
            DontCare,
        ])
        .mem_size_pairs(&pairs::TRACE_VPRINTK)
        .ret(RetKind::Scalar),

        constants::BPF_STRTOUL => {
            CallProto::with_args([PtrToMem, ConstSize, Anything, PtrToLong, DontCare])
        }

        constants::BPF_STRTOL => {
            CallProto::with_args([PtrToMem, ConstSize, Anything, PtrToLong, DontCare])
        }

        constants::BPF_CHECK_MTU => CallProto::with_args([
            PtrToCtx,       // R1: ctx (skb / xdp_md)
            Anything,       // R2: ifindex
            PtrToUninitMem, // R3: u32 *mtu_len — writable; rdonly-map gated
            Anything,       // R4: len_diff
            Anything,       // R5: flags
        ]),

        constants::BPF_COPY_FROM_USER => CallProto::with_args([
            PtrToUninitMem, // R1: dst — writable; rdonly-map gated
            ConstSize,      // R2: size
            Anything,       // R3: user_ptr
            DontCare,
            DontCare,
        ])
        .flags(CallFlags::MIGHT_SLEEP),

        // bpf_copy_from_user_task(void *dst, u32 size, const void __user
        // *src, struct task_struct *task, u64 flags) — sleepable variant
        // that reads from another task's address space. Required as a
        // *helper* proto (helper id 191) so the MIGHT_SLEEP gate fires
        // when called inside an RCU read region — closes
        // rcu_read_lock::inproper_sleepable_helper. R4 uses bare
        // `PtrToBtfId` (any BTF id) rather than `PtrToBtfIdNamed{"task_struct"}`
        // because kernel selftests pass `task_struct___local`-typed
        // subprog args via `__arg_trusted` (libbpf rewrites the FUNC
        // proto to a local struct alias for CO-RE compatibility);
        // strict-name matching breaks `verifier_global_ptr_args::flavor_ptr_*`.
        constants::BPF_COPY_FROM_USER_TASK => CallProto::with_args([
            PtrToUninitMem, // R1: dst
            ConstSize,      // R2: size
            Anything,       // R3: user_ptr
            PtrToBtfId,     // R4: task (any BTF id; libbpf alias-tolerant)
            Anything,       // R5: flags
        ])
        .mem_size_pairs(&pairs::COPY_FROM_USER_STR)
        .flags(CallFlags::MIGHT_SLEEP),

        constants::BPF_GET_CGROUP_CLASS_ID => {
            CallProto::with_args([PtrToCtx, DontCare, DontCare, DontCare, DontCare])
        }

        constants::BPF_GET_CURRENT_COMM => CallProto::with_args([
            PtrToUninitMem, // R1: buf (output buffer for comm string)
            ConstSize,      // R2: size_of_buf
            DontCare,
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::GET_CURRENT_COMM),

        constants::BPF_PERF_EVENT_OUTPUT => CallProto::with_args([
            PtrToCtx,         // R1: ctx
            ConstMapPtr,      // R2: map
            Anything,         // R3: flags
            PtrToMem,         // R4: data
            ConstSizeOrZero,  // R5: size — kernel uses ARG_CONST_SIZE_OR_ZERO
        ])
        .mem_size_pairs(&pairs::PERF_EVENT_OUTPUT),

        constants::BPF_L3_CSUM_REPLACE => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: offset
            Anything, // R3: from
            Anything, // R4: to
            Anything, // R5: flags
        ]),

        constants::BPF_L4_CSUM_REPLACE => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: offset
            Anything, // R3: from
            Anything, // R4: to
            Anything, // R5: flags
        ]),

        // ---- storage_get/_delete (sk + task + inode) ----
        // R0 typing for *_storage_get is handled by the legacy
        // `update_call_types` arm in transfer/types.rs, which keys
        // PtrToMapValueOrNull off R1 (the map) — same pattern as
        // bpf_get_local_storage. The arg-side proto is identical across
        // the three families; only R2's expected ptr family differs
        // (sock_common vs btf_id task vs btf_id inode).
        constants::BPF_SK_STORAGE_DELETE => CallProto::with_args([
            ConstMapPtr,            // R1: map
            PtrToBTFIdSockCommon,   // R2: sk
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        constants::BPF_TASK_STORAGE_GET => CallProto::with_args([
            ConstMapPtr,            // R1: map
            PtrToTask,              // R2: task
            PtrToMapValueOrNull,    // R3: value (may be NULL)
            Anything,               // R4: flags
            DontCare,
        ]),

        constants::BPF_TASK_STORAGE_DELETE => CallProto::with_args([
            ConstMapPtr,            // R1: map
            PtrToTask,              // R2: task
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        constants::BPF_INODE_STORAGE_GET => CallProto::with_args([
            ConstMapPtr,            // R1: map
            PtrToBtfId,             // R2: inode
            PtrToMapValueOrNull,    // R3: value
            Anything,               // R4: flags
            DontCare,
        ]),

        constants::BPF_INODE_STORAGE_DELETE => CallProto::with_args([
            ConstMapPtr,            // R1: map
            PtrToBtfId,             // R2: inode
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_cgrp_storage_get(map, cgroup, value, flags)
        // R0 typing handled by `update_call_types` (PtrToMapValueOrNull
        // keyed off R1's map). Arg-side: R2 must be a `cgroup` PtrToBtfId
        // — the typical bug (cgrp_ls_negative.c::on_enter) is passing a
        // task_struct cast as cgroup; PtrToBtfIdNamed catches the type
        // mismatch.
        constants::BPF_CGRP_STORAGE_GET => CallProto::with_args([
            ConstMapPtr,                                  // R1: map
            PtrToBtfIdNamed { type_name: "cgroup" },      // R2: cgroup
            PtrToMapValueOrNull,                          // R3: value
            Anything,                                     // R4: flags
            DontCare,
        ]),

        constants::BPF_CGRP_STORAGE_DELETE => CallProto::with_args([
            ConstMapPtr,                                  // R1: map
            PtrToBtfIdNamed { type_name: "cgroup" },      // R2: cgroup
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- bpf_get_current_task_btf ----
        // Returns the kernel's current-task pointer, typed as PTR_TO_BTF_ID
        // (task_struct *) with PTR_TRUSTED. Modeled here as PtrToTask (no
        // ACQUIRE — the kernel guarantees the returned pointer is live for
        // the duration of the program). Zero arguments.
        constants::BPF_GET_CURRENT_TASK_BTF => CallProto::with_args([
            DontCare, DontCare, DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::PtrToTask),

        // ---- bpf_d_path ----
        // (path: struct path *, buf: writable, sz: const) -> s64
        constants::BPF_D_PATH => CallProto::with_args([
            PtrToBtfId,     // R1: struct path *
            PtrToUninitMem, // R2: buf
            ConstSize,      // R3: sz
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::D_PATH)
        .ret(RetKind::Scalar),

        // ---- bpf_snprintf ----
        // (buf, sz, fmt, data, data_len) -> s32
        // Lite scope: fmt and data are accepted as PtrToMem; the kernel
        // additionally validates fmt against const-rodata + matches data
        // entries against fmt specifiers (not modeled).
        constants::BPF_SNPRINTF => CallProto::with_args([
            PtrToUninitMemOrNull, // R1: buf (NULL OK with size=0; "compute length only")
            ConstSizeOrZero,      // R2: sz
            PtrToConstStr,        // R3: fmt — must be const string in rodata map
            PtrToMemOrNull,  // R4: data (u64 array; may be NULL if data_len=0)
            ConstSizeOrZero, // R5: data_len
        ])
        .mem_size_pairs(&pairs::SNPRINTF)
        .ret(RetKind::Scalar),

        // ---- bpf_strncmp ----
        // (s1: PtrToMem, s1_sz: ConstSize, s2: PtrToConstStr) -> s32
        // Kernel rejects writable / non-NUL-terminated comparands via
        // ARG_PTR_TO_CONST_STR (validate_ptr_to_const_str enforces
        // BPF_F_RDONLY_PROG + NUL-within-rodata-bounds). Closes
        // strncmp_bad_writable_target and strncmp_bad_not_null_term_target.
        constants::BPF_STRNCMP => CallProto::with_args([
            PtrToMem,       // R1: s1
            ConstSize,      // R2: s1_sz
            PtrToConstStr,  // R3: s2 (rodata, NUL-terminated)
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::STRNCMP)
        .ret(RetKind::Scalar),

        // ---- Dynptr helpers ----
        //
        // These are real helpers (numeric BPF_FUNC_* ids in v6.15 uapi),
        // not kfuncs — clang emits CALL insns with the helper id, not
        // PSEUDO_KFUNC_CALL. Their prototypes happen to live in the
        // name-keyed table next to the related kfuncs (slice/from_skb/
        // from_xdp); delegate by name so we don't duplicate them. Without
        // these arms the entire dynptr modeling (init/release/leak
        // detection) is unreachable on numeric-helper calls.
        constants::BPF_DYNPTR_FROM_MEM => return get_kfunc_proto("bpf_dynptr_from_mem"),
        constants::BPF_RINGBUF_RESERVE_DYNPTR => {
            return get_kfunc_proto("bpf_ringbuf_reserve_dynptr");
        }
        constants::BPF_RINGBUF_SUBMIT_DYNPTR => {
            return get_kfunc_proto("bpf_ringbuf_submit_dynptr");
        }
        constants::BPF_RINGBUF_DISCARD_DYNPTR => {
            return get_kfunc_proto("bpf_ringbuf_discard_dynptr");
        }
        constants::BPF_DYNPTR_READ => return get_kfunc_proto("bpf_dynptr_read"),
        constants::BPF_DYNPTR_WRITE => return get_kfunc_proto("bpf_dynptr_write"),
        constants::BPF_DYNPTR_DATA => return get_kfunc_proto("bpf_dynptr_data"),

        // ============================================================
        // Helper proto enumeration, batch 1. Every shape below
        // mirrors the kernel proto (kernel/bpf/helpers.c,
        // net/core/filter.c, kernel/trace/bpf_trace.c,
        // drivers/media/rc/bpf-lirc.c, kernel/bpf/stackmap.c,
        // kernel/bpf/cgroup.c, net/ipv4/bpf_tcp_ca.c) on v6.18-rc4
        // (= the BPF_FUNC_MAPPER from vendor/linux uapi). R0 typing
        // is RET_INTEGER (scalar) for all entries in this batch.
        // ============================================================

        // ---- Process / time / ID helpers (no-arg or pure-scalar) ----
        // bpf_get_smp_processor_id() -> u32. kernel allow_fastcall.
        constants::BPF_GET_SMP_PROCESSOR_ID => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        // bpf_get_current_cgroup_id() -> u64.
        constants::BPF_GET_CURRENT_CGROUP_ID => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        // bpf_jiffies64() -> u64.
        constants::BPF_JIFFIES64 => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        // bpf_send_signal_thread(sig) -> long.
        constants::BPF_SEND_SIGNAL_THREAD => CallProto::with_args([
            Anything, // R1: sig
            DontCare, DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- SKB ctx + scalar arg helpers ----
        // bpf_skb_cgroup_id(skb) -> u64.
        constants::BPF_SKB_CGROUP_ID => CallProto::with_args([
            PtrToCtx, // R1: skb
            DontCare, DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_skb_ancestor_cgroup_id(skb, ancestor_level) -> u64.
        constants::BPF_SKB_ANCESTOR_CGROUP_ID => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: ancestor_level
            DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_csum_level(skb, level) -> int.
        constants::BPF_CSUM_LEVEL => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: level
            DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- Tunnel option helpers (ctx + mem + size) ----
        // bpf_skb_get_tunnel_opt(skb, opt_buf, size) -> int. Writes opt_buf.
        constants::BPF_SKB_GET_TUNNEL_OPT => CallProto::with_args([
            PtrToCtx,       // R1: skb
            PtrToUninitMem, // R2: opt (writable buffer)
            ConstSize,      // R3: size
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::SKB_GET_TUNNEL_OPT)
        .ret(RetKind::Scalar),
        // bpf_skb_set_tunnel_opt(skb, opt, size) -> int. Reads opt.
        constants::BPF_SKB_SET_TUNNEL_OPT => CallProto::with_args([
            PtrToCtx,  // R1: skb
            PtrToMem,  // R2: opt (rdonly source buffer)
            ConstSize, // R3: size
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::SKB_SET_TUNNEL_OPT)
        .ret(RetKind::Scalar),

        // bpf_skb_get_xfrm_state(skb, index, xfrm_state, size, flags) -> int.
        constants::BPF_SKB_GET_XFRM_STATE => CallProto::with_args([
            PtrToCtx,       // R1: skb
            Anything,       // R2: index
            PtrToUninitMem, // R3: xfrm_state (writable)
            ConstSize,      // R4: size
            Anything,       // R5: flags
        ])
        .mem_size_pairs(&pairs::SKB_GET_XFRM_STATE)
        .ret(RetKind::Scalar),
        // bpf_skb_load_bytes_relative(skb, off, to, len, start_hdr) -> int.
        constants::BPF_SKB_LOAD_BYTES_RELATIVE => CallProto::with_args([
            PtrToCtx,       // R1: skb
            Anything,       // R2: offset
            PtrToUninitMem, // R3: to (writable)
            ConstSize,      // R4: len
            Anything,       // R5: start_header
        ])
        .mem_size_pairs(&pairs::SKB_LOAD_BYTES_RELATIVE)
        .ret(RetKind::Scalar),

        // ---- Sock helpers / setsockopt / bind / sock_ops ----
        // bpf_setsockopt(ctx_or_sock, level, optname, optval, optlen) -> int.
        // Kernel has 3 protos keyed by ProgramKind (sock_addr_setsockopt,
        // sock_ops_setsockopt, unlocked_sk_setsockopt). R1 differs:
        // sock_addr/sock_ops use ARG_PTR_TO_CTX; unlocked uses
        // ARG_PTR_TO_BTF_ID_SOCK_COMMON. R2..R5 are identical across the
        // three. We model R1 as `Anything` to accept all three call sites
        // (the ctx-shape check is per-prog-type and the kernel rejects
        // mismatches at the helper-dispatch layer; we'd need
        // prog_type_allowlist to fully model — out of scope here, ≤BCF
        // preserved because the prior reject was a zovia-only false neg).
        constants::BPF_SETSOCKOPT => CallProto::with_args([
            Anything,  // R1: ctx (sock_addr/sock_ops) or btf-sock (unlocked)
            Anything,  // R2: level
            Anything,  // R3: optname
            PtrToMem,  // R4: optval (rdonly)
            ConstSize, // R5: optlen
        ])
        .mem_size_pairs(&pairs::SETSOCKOPT)
        .ret(RetKind::Scalar),
        // bpf_bind(ctx, addr, addr_len) -> int.
        constants::BPF_BIND => CallProto::with_args([
            PtrToCtx,  // R1: bpf_sock_addr
            PtrToMem,  // R2: addr (rdonly)
            ConstSize, // R3: addr_len
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::BIND)
        .ret(RetKind::Scalar),
        // bpf_sock_ops_cb_flags_set(sock_ops, flags) -> int.
        constants::BPF_SOCK_OPS_CB_FLAGS_SET => CallProto::with_args([
            PtrToCtx, // R1: bpf_sock_ops
            Anything, // R2: argval
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- Redirect-map family (xdp / sk / msg) ----
        // bpf_redirect_map(map, key, flags) -> int. xdp variant — no ctx;
        // the helper id is overloaded across program types. The other
        // variants (id 52 sk_redirect_map, id 60 msg_redirect_map) take
        // a ctx as R1.
        constants::BPF_REDIRECT_MAP => CallProto::with_args([
            ConstMapPtr, // R1: map
            Anything,    // R2: key
            Anything,    // R3: flags
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_sk_redirect_map(skb, map, key, flags) -> int.
        constants::BPF_SK_REDIRECT_MAP => CallProto::with_args([
            PtrToCtx,    // R1: skb
            ConstMapPtr, // R2: map
            Anything,    // R3: key
            Anything,    // R4: flags
            DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_msg_redirect_map(msg, map, key, flags) -> int.
        constants::BPF_MSG_REDIRECT_MAP => CallProto::with_args([
            PtrToCtx,    // R1: sk_msg
            ConstMapPtr, // R2: map
            Anything,    // R3: key
            Anything,    // R4: flags
            DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_sock_hash_update(ctx, map, key, flags) -> int.
        constants::BPF_SOCK_HASH_UPDATE => CallProto::with_args([
            PtrToCtx,    // R1: bpf_sock_ops_kern
            ConstMapPtr, // R2: map
            PtrToMapKey, // R3: key
            Anything,    // R4: flags
            DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_sk_select_reuseport(reuse_kern, map, key, flags) -> int.
        constants::BPF_SK_SELECT_REUSEPORT => CallProto::with_args([
            PtrToCtx,    // R1: sk_reuseport_md
            ConstMapPtr, // R2: map
            PtrToMapKey, // R3: key
            Anything,    // R4: flags
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- LWT (lightweight tunnel) helpers ----
        // bpf_lwt_in_push_encap / bpf_lwt_xmit_push_encap (same shape;
        // kernel dispatches by attach hook). (ctx, type, hdr, len) -> int.
        constants::BPF_LWT_PUSH_ENCAP => CallProto::with_args([
            PtrToCtx,  // R1: skb
            Anything,  // R2: type
            PtrToMem,  // R3: hdr (rdonly)
            ConstSize, // R4: len
            DontCare,
        ])
        .mem_size_pairs(&pairs::LWT_PUSH_ENCAP)
        .ret(RetKind::Scalar),
        // bpf_lwt_seg6_adjust_srh(ctx, offset, len) -> int.
        constants::BPF_LWT_SEG6_ADJUST_SRH => CallProto::with_args([
            PtrToCtx, // R1: skb
            Anything, // R2: offset
            Anything, // R3: len
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_lwt_seg6_action(ctx, action, param, param_len) -> int.
        constants::BPF_LWT_SEG6_ACTION => CallProto::with_args([
            PtrToCtx,  // R1: skb
            Anything,  // R2: action
            PtrToMem,  // R3: param (rdonly)
            ConstSize, // R4: param_len
            DontCare,
        ])
        .mem_size_pairs(&pairs::LWT_SEG6_ACTION)
        .ret(RetKind::Scalar),

        // ---- Stack-ID + override-return + IR + sysctl ----
        // bpf_get_stackid(ctx, map, flags) -> int.
        constants::BPF_GET_STACKID => CallProto::with_args([
            PtrToCtx,    // R1: ctx (pt_regs / xdp_md / skb / ...)
            ConstMapPtr, // R2: stackmap
            Anything,    // R3: flags
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_override_return(pt_regs, rc) -> int. kprobe-only in kernel
        // (gpl_only). Modeled with PtrToCtx for R1 — kprobe ctx.
        constants::BPF_OVERRIDE_RETURN => CallProto::with_args([
            PtrToCtx, // R1: pt_regs
            Anything, // R2: rc
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_rc_keydown(ctx, protocol, scancode, toggle) -> int. LIRC mode2.
        constants::BPF_RC_KEYDOWN => CallProto::with_args([
            PtrToCtx, // R1: bpf_lirc_mode2 ctx
            Anything, // R2: protocol
            Anything, // R3: scancode
            Anything, // R4: toggle
            DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_probe_write_user(dst_user, src, size) -> int. dst is
        // ARG_ANYTHING (user-space pointer, not validated).
        constants::BPF_PROBE_WRITE_USER => CallProto::with_args([
            Anything,  // R1: dst (user pointer)
            PtrToMem,  // R2: src (rdonly source)
            ConstSize, // R3: size
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::PROBE_WRITE_USER)
        .ret(RetKind::Scalar),
        // bpf_sysctl_get_name(ctx, buf, len, flags) -> int. buf is
        // MEM_WRITE; modeled as PtrToUninitMem (zovia's writable-mem
        // gate, mirrors existing get_sockopt / check_mtu pattern).
        constants::BPF_SYSCTL_GET_NAME => CallProto::with_args([
            PtrToCtx,       // R1: bpf_sysctl
            PtrToUninitMem, // R2: buf (writable)
            ConstSize,      // R3: buf_len
            Anything,       // R4: flags
            DontCare,
        ])
        .mem_size_pairs(&pairs::SYSCTL_GET_NAME)
        .ret(RetKind::Scalar),

        // ---- TCP / branch records / get_ns_pid_tgid ----
        // bpf_tcp_send_ack(tcp_sock, rcv_nxt) -> int. R1 is a kernel
        // `struct tcp_sock *` BTF-id pointer (kernel ARG_PTR_TO_BTF_ID
        // with tcp_sock_id). PtrToBtfIdNamed{"tcp_sock"} matches.
        constants::BPF_TCP_SEND_ACK => CallProto::with_args([
            PtrToBtfIdNamed { type_name: "tcp_sock" }, // R1: tcp_sock
            Anything,                                  // R2: rcv_nxt
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_read_branch_records(ctx, buf, size, flags) -> int. buf is
        // ARG_PTR_TO_MEM_OR_NULL with ARG_CONST_SIZE_OR_ZERO size.
        constants::BPF_READ_BRANCH_RECORDS => CallProto::with_args([
            PtrToCtx,         // R1: perf ctx
            PtrToMemOrNull,   // R2: buf
            ConstSizeOrZero,  // R3: size
            Anything,         // R4: flags
            DontCare,
        ])
        .mem_size_pairs(&pairs::READ_BRANCH_RECORDS)
        .ret(RetKind::Scalar),
        // bpf_get_ns_current_pid_tgid(dev, ino, nsdata, size) -> int.
        // R1/R2 = ARG_ANYTHING (dev/ino scalars), R3 = uninit_mem, R4 =
        // const_size.
        constants::BPF_GET_NS_CURRENT_PID_TGID => CallProto::with_args([
            Anything,       // R1: dev
            Anything,       // R2: ino
            PtrToUninitMem, // R3: nsdata
            ConstSize,      // R4: size
            DontCare,
        ])
        .mem_size_pairs(&pairs::GET_NS_CURRENT_PID_TGID)
        .ret(RetKind::Scalar),

        // ---- seq_file helpers (BPF iterators) ----
        // bpf_seq_printf(seq, fmt, fmt_sz, data, data_len) -> int. R1 is
        // ARG_PTR_TO_BTF_ID with seq_file btf-id; R4/R5 is the
        // nullable data array pair.
        constants::BPF_SEQ_PRINTF => CallProto::with_args([
            PtrToBtfIdNamed { type_name: "seq_file" }, // R1: seq
            PtrToMem,                                  // R2: fmt (rdonly)
            ConstSize,                                 // R3: fmt_size
            PtrToMemOrNull,                            // R4: data (u64[])
            ConstSizeOrZero,                           // R5: data_len
        ])
        .mem_size_pairs(&pairs::SEQ_PRINTF)
        .ret(RetKind::Scalar),
        // bpf_seq_write(seq, data, len) -> int. size_or_zero accepted.
        constants::BPF_SEQ_WRITE => CallProto::with_args([
            PtrToBtfIdNamed { type_name: "seq_file" }, // R1: seq
            PtrToMem,                                  // R2: data (rdonly)
            ConstSizeOrZero,                           // R3: len
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::SEQ_WRITE)
        .ret(RetKind::Scalar),

        // bpf_skb_event_output (helper id 111 BPF_SKB_OUTPUT): like
        // bpf_perf_event_output but R1 is a kernel `struct sk_buff *`
        // BTF-id pointer (tracing/raw_tp programs that received the skb
        // as a kernel struct). R5 is size_or_zero.
        constants::BPF_SKB_OUTPUT => CallProto::with_args([
            PtrToBtfIdNamed { type_name: "sk_buff" }, // R1: sk_buff
            ConstMapPtr,                              // R2: map (PERF_EVENT_ARRAY)
            Anything,                                 // R3: flags
            PtrToMem,                                 // R4: data (rdonly)
            ConstSizeOrZero,                          // R5: size
        ])
        .mem_size_pairs(&pairs::SKB_OUTPUT)
        .ret(RetKind::Scalar),

        // ============================================================
        // Helper proto enumeration, batch 2:
        // BTF-typed sock casts, per-cpu pointer, map-element queue,
        // ringbuf_discard, probe_read_str variants, tracing/retval
        // helpers, syscall/snprintf_btf/sysbpf, etc.
        //
        // R0 typing for sock-cast / per-cpu / task / file helpers is
        // already handled by the legacy arms in
        // `transfer::types::update_call_types`; those entries use the
        // default `RetKind::Unknown` so the proto-side applier defers
        // to legacy. Pure RET_INTEGER entries use `RetKind::Scalar`.
        // ============================================================

        // ---- Map-element queue/stack helpers ----
        // bpf_map_push_elem(map, value, flags) -> int. R2 reads value.
        constants::BPF_MAP_PUSH_ELEM => CallProto::with_args([
            ConstMapPtr,   // R1: map (QUEUE/STACK)
            PtrToMapValue, // R2: value
            Anything,      // R3: flags
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_map_pop_elem(map, value) -> int. R2 is writable, uninit.
        constants::BPF_MAP_POP_ELEM => CallProto::with_args([
            ConstMapPtr,         // R1: map
            PtrToUninitMapValue, // R2: value (writable)
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_map_peek_elem(map, value) -> int. Same shape as POP.
        constants::BPF_MAP_PEEK_ELEM => CallProto::with_args([
            ConstMapPtr,         // R1: map
            PtrToUninitMapValue, // R2: value (writable)
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- Ringbuf discard (legacy API, parallel to RINGBUF_SUBMIT) ----
        // bpf_ringbuf_discard(data, flags). Mirrors RINGBUF_SUBMIT —
        // both consume an alloc-mem pointer. Modeled here as a Scalar
        // return; kernel RET_VOID but BPF callers see scalar R0.
        constants::BPF_RINGBUF_DISCARD => {
            CallProto::with_args([PtrToAllocMem, Anything, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- probe_read_*_str variants (mirror PROBE_READ shape) ----
        // bpf_probe_read_user_str(dst, size, user_ptr) -> int.
        constants::BPF_PROBE_READ_USER_STR => CallProto::with_args([
            PtrToUninitMem,  // R1: dst
            ConstSizeOrZero, // R2: size
            Anything,        // R3: unsafe_ptr (user)
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::PROBE_READ)
        .ret(RetKind::Scalar),
        // bpf_probe_read_kernel_str(dst, size, kernel_ptr) -> int.
        constants::BPF_PROBE_READ_KERNEL_STR => CallProto::with_args([
            PtrToUninitMem,  // R1: dst
            ConstSizeOrZero, // R2: size
            Anything,        // R3: unsafe_ptr (kernel)
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::PROBE_READ)
        .ret(RetKind::Scalar),

        // ---- BTF-typed sock cast helpers (skc_to_*) ----
        // R0 typing in update_call_types matches `kernel struct` names
        // (tcp_sock / tcp6_sock / tcp_request_sock / unix_sock /
        // mptcp_sock). Kernel arg1 = ARG_PTR_TO_BTF_ID_SOCK_COMMON
        // except mptcp_sock which uses ARG_PTR_TO_SOCK_COMMON.
        constants::BPF_SKC_TO_TCP_SOCK => CallProto::with_args([
            PtrToBTFIdSockCommon, // R1: sock_common
            DontCare, DontCare, DontCare, DontCare,
        ]),
        constants::BPF_SKC_TO_TCP6_SOCK => CallProto::with_args([
            PtrToBTFIdSockCommon,
            DontCare, DontCare, DontCare, DontCare,
        ]),
        constants::BPF_SKC_TO_TCP_REQUEST_SOCK => CallProto::with_args([
            PtrToBTFIdSockCommon,
            DontCare, DontCare, DontCare, DontCare,
        ]),
        constants::BPF_SKC_TO_UNIX_SOCK => CallProto::with_args([
            PtrToBTFIdSockCommon,
            DontCare, DontCare, DontCare, DontCare,
        ]),
        constants::BPF_SKC_TO_MPTCP_SOCK => CallProto::with_args([
            PtrToSockCommon, // R1: sock_common (no BTF wrapping per kernel)
            DontCare, DontCare, DontCare, DontCare,
        ]),

        // bpf_get_listener_sock(sock) -> sock_or_null. R0 typed by
        // legacy update_call_types arm (PtrToSocketOrNull, no ref).
        constants::BPF_GET_LISTENER_SOCK => CallProto::with_args([
            PtrToSockCommon, // R1: sock_common
            DontCare, DontCare, DontCare, DontCare,
        ]),

        // bpf_sock_from_file(file) -> socket_or_null. R0 typed by
        // legacy arm as PtrToBtfIdOrNull{"socket", TRUSTED}. Kernel
        // arg1 = ARG_PTR_TO_BTF_ID with bpf_sock_from_file_btf_ids[1]
        // = `struct file *`. PtrToBtfIdNamed{"file"} enforces that.
        constants::BPF_SOCK_FROM_FILE => CallProto::with_args([
            PtrToBtfIdNamed { type_name: "file" }, // R1: file
            DontCare, DontCare, DontCare, DontCare,
        ]),

        // bpf_task_pt_regs(task) -> pt_regs. R0 typed by legacy arm.
        constants::BPF_TASK_PT_REGS => CallProto::with_args([
            PtrToTask, // R1: task_struct
            DontCare, DontCare, DontCare, DontCare,
        ]),

        // ---- per-cpu / this-cpu ptr (R0 typing legacy) ----
        // Kernel arg1 = ARG_PTR_TO_PERCPU_BTF_ID. zovia accepts the
        // input via legacy R0-typing in update_call_types which handles
        // both `PtrToBtfId` (typed __ksym) and `PtrToMapKptr` (per-cpu
        // map field) inputs. The arg-side `Anything` lets either pass;
        // the R0 typer rejects unresolved inputs by leaving R0 scalar.
        constants::BPF_PER_CPU_PTR => CallProto::with_args([
            Anything, // R1: percpu_ptr (typed __ksym or map_kptr)
            Anything, // R2: cpu
            DontCare, DontCare, DontCare,
        ]),
        constants::BPF_THIS_CPU_PTR => CallProto::with_args([
            Anything, // R1: percpu_ptr
            DontCare, DontCare, DontCare, DontCare,
        ]),

        // ---- Tracing helpers (get_func_ip / get_attach_cookie / ...) ----
        // bpf_get_func_ip(ctx) -> u64. Multiple kernel protos
        // (kprobe / tracing / kprobe_multi / uprobe_multi) all share
        // (PtrToCtx) -> RET_INTEGER shape.
        constants::BPF_GET_FUNC_IP => CallProto::with_args([
            PtrToCtx, // R1: ctx (pt_regs / tracing ctx)
            DontCare, DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_get_attach_cookie(ctx) -> u64. Multiple kernel protos
        // (perf_event / kprobe / kprobe_multi / uprobe_multi / trace);
        // all share (PtrToCtx) -> RET_INTEGER.
        constants::BPF_GET_ATTACH_COOKIE => CallProto::with_args([
            PtrToCtx, // R1: ctx
            DontCare, DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_get_func_arg_cnt(ctx) -> int.
        constants::BPF_GET_FUNC_ARG_CNT => CallProto::with_args([
            PtrToCtx, // R1: tracing ctx
            DontCare, DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- Cgroup-prog retval helpers ----
        // bpf_get_retval() -> int. No args.
        constants::BPF_GET_RETVAL => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }
        // bpf_set_retval(rc) -> int.
        constants::BPF_SET_RETVAL => CallProto::with_args([
            Anything, // R1: rc
            DontCare, DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),

        // ---- XDP buf-len / load-bytes ----
        // bpf_xdp_get_buff_len(xdp_md) -> u64.
        constants::BPF_XDP_GET_BUFF_LEN => CallProto::with_args([
            PtrToCtx, // R1: xdp_md
            DontCare, DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_xdp_load_bytes(ctx, off, buf, len) -> int.
        constants::BPF_XDP_LOAD_BYTES => CallProto::with_args([
            PtrToCtx,       // R1: xdp_md
            Anything,       // R2: offset
            PtrToUninitMem, // R3: buf
            ConstSize,      // R4: len
            DontCare,
        ])
        .mem_size_pairs(&pairs::XDP_LOAD_BYTES)
        .ret(RetKind::Scalar),

        // bpf_ktime_get_tai_ns() -> u64.
        constants::BPF_KTIME_GET_TAI_NS => {
            CallProto::with_args([DontCare, DontCare, DontCare, DontCare, DontCare])
                .ret(RetKind::Scalar)
        }

        // ---- LSM ----
        // bpf_bprm_opts_set(bprm, flags) -> int. R1 = struct linux_binprm.
        constants::BPF_BPRM_OPTS_SET => CallProto::with_args([
            PtrToBtfIdNamed { type_name: "linux_binprm" }, // R1: bprm
            Anything,                                      // R2: flags
            DontCare, DontCare, DontCare,
        ])
        .ret(RetKind::Scalar),
        // bpf_ima_inode_hash(inode, dst, size) -> int. MIGHT_SLEEP.
        constants::BPF_IMA_INODE_HASH => CallProto::with_args([
            PtrToBtfIdNamed { type_name: "inode" }, // R1: inode
            PtrToUninitMem,                         // R2: dst
            ConstSize,                              // R3: size
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::IMA_INODE_HASH)
        .flags(CallFlags::MIGHT_SLEEP)
        .ret(RetKind::Scalar),

        // ---- Syscall helper ----
        // bpf_sys_bpf(cmd, attr, attr_size) -> int. tracing/syscall prog
        // type can call this; arg2 is rdonly mem.
        constants::BPF_SYS_BPF => CallProto::with_args([
            Anything,  // R1: cmd
            PtrToMem,  // R2: attr (rdonly)
            ConstSize, // R3: attr_size
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::SYS_BPF)
        .ret(RetKind::Scalar),

        // ---- snprintf_btf (BTF type-aware snprintf) ----
        // bpf_snprintf_btf(str, str_sz, ptr, ptr_size, flags) -> int.
        // Kernel proto: arg1 = ARG_PTR_TO_MEM (output buf; kernel
        // doesn't set MEM_WRITE explicitly but writes to it). arg2 =
        // CONST_SIZE. arg3 = PTR_TO_MEM|MEM_RDONLY (btf_ptr struct).
        // arg4 = CONST_SIZE. arg5 = ANYTHING. We use PtrToUninitMem for
        // R1 (tighter; matches the helper's write semantic and
        // mirrors snprintf's R1 convention) and PtrToMem for R3.
        constants::BPF_SNPRINTF_BTF => CallProto::with_args([
            PtrToUninitMem, // R1: str (writable output)
            ConstSize,      // R2: str_size
            PtrToMem,       // R3: btf_ptr (rdonly)
            ConstSize,      // R4: btf_ptr_size
            Anything,       // R5: flags
        ])
        .mem_size_pairs(&pairs::SNPRINTF_BTF)
        .ret(RetKind::Scalar),

        // ---- sock_ops header-option helper ----
        // bpf_sock_ops_load_hdr_opt(ctx, search, len, flags) -> int.
        // arg2 is MEM_WRITE — the helper writes the matched option's
        // payload into the buffer. PtrToUninitMem matches.
        constants::BPF_LOAD_HDR_OPT => CallProto::with_args([
            PtrToCtx,       // R1: bpf_sock_ops_kern
            PtrToUninitMem, // R2: search (writable)
            ConstSize,      // R3: search_len
            Anything,       // R4: flags
            DontCare,
        ])
        .mem_size_pairs(&pairs::LOAD_HDR_OPT)
        .ret(RetKind::Scalar),

        // ---- TCP raw syncookie (IPv4 + IPv6, gen + check) ----
        // Kernel arg1 (and arg2 for the `check_` pair) is
        // ARG_PTR_TO_FIXED_SIZE_MEM; we don't model fixed-size mem here,
        // so it falls through to plain PtrToMem (kernel verifies the
        // fixed size internally on its side). For `gen_`, arg2/arg3 is
        // the normal mem+size pair (R2 mem, R3 const_size_or_zero).
        // For `check_`, both args are fixed-size pointers, no size reg.
        // bpf_tcp_raw_gen_syncookie_ipv4(iph, th, th_len) -> int.
        constants::BPF_TCP_RAW_GEN_SYNCOOKIE_IPV4 => CallProto::with_args([
            PtrToMem,        // R1: iph (kernel verifies fixed size internally)
            PtrToMem,        // R2: th
            ConstSizeOrZero, // R3: th_len
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::TCP_RAW_GEN_SYNCOOKIE_IPV4)
        .ret(RetKind::Scalar),

        // bpf_tcp_raw_gen_syncookie_ipv6(iph, th, th_len) -> int.
        constants::BPF_TCP_RAW_GEN_SYNCOOKIE_IPV6 => CallProto::with_args([
            PtrToMem,        // R1: iph (kernel verifies fixed size internally)
            PtrToMem,        // R2: th
            ConstSizeOrZero, // R3: th_len
            DontCare,
            DontCare,
        ])
        .mem_size_pairs(&pairs::TCP_RAW_GEN_SYNCOOKIE_IPV6)
        .ret(RetKind::Scalar),

        // bpf_tcp_raw_check_syncookie_ipv4(iph, th) -> int.
        // Both args are FIXED_SIZE_MEM; no explicit size register.
        constants::BPF_TCP_RAW_CHECK_SYNCOOKIE_IPV4 => CallProto::with_args([
            PtrToMem, // R1: iph (kernel verifies fixed size internally)
            PtrToMem, // R2: th (kernel verifies fixed size internally)
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_tcp_raw_check_syncookie_ipv6(iph, th) -> int.
        constants::BPF_TCP_RAW_CHECK_SYNCOOKIE_IPV6 => CallProto::with_args([
            PtrToMem, // R1: iph (kernel verifies fixed size internally)
            PtrToMem, // R2: th (kernel verifies fixed size internally)
            DontCare,
            DontCare,
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // ============================================================
        // Helper proto enumeration, batch 3:
        // callback helpers (bpf_loop, bpf_find_vma) and kptr_xchg.
        //
        // bpf_loop / bpf_find_vma are already recognized by
        // `is_callback_helper`; the helper dispatcher routes through
        // `transfer_callback_helper` which forks the call into an
        // enter-callback successor (the subprog gets a fresh frame
        // with typed args) and a skip-callback successor. The proto
        // here is required so `validate_helper_args` admits the call
        // shape before the dispatcher runs. R3 callback_ctx is modeled
        // as `Anything` to match the existing FOR_EACH_MAP_ELEM /
        // USER_RINGBUF_DRAIN convention (kernel
        // ARG_PTR_TO_STACK_OR_NULL is verified by the cb-frame typer).
        //
        // bpf_kptr_xchg has bespoke arg + R0 handling in
        // `transfer::call::transfer::transfer_helper_call` (kptr field
        // resolution, ref consumption, R0 = PtrToMapKptrOrNull). The
        // proto here uses `Anything`/`Anything` so validate_helper_args
        // admits the call; the kptr_xchg branch does the real work and
        // returns early, so RetKind::Unknown is correct (the legacy R0
        // path is never reached for this helper).
        // ============================================================

        // bpf_loop(nr_loops, callback_fn, callback_ctx, flags) -> int.
        constants::BPF_LOOP => CallProto::with_args([
            Anything,      // R1: nr_loops
            PtrToCallback, // R2: callback_fn
            Anything,      // R3: callback_ctx (stack-or-null)
            Anything,      // R4: flags
            DontCare,
        ])
        .ret(RetKind::Scalar),

        // bpf_find_vma(task, addr, callback_fn, callback_ctx, flags) -> int.
        constants::BPF_FIND_VMA => CallProto::with_args([
            PtrToTask,     // R1: task
            Anything,      // R2: addr
            PtrToCallback, // R3: callback_fn
            Anything,      // R4: callback_ctx (stack-or-null)
            Anything,      // R5: flags
        ])
        .ret(RetKind::Scalar),

        // bpf_kptr_xchg(map_value+kptr_off, kptr) -> kptr_or_null.
        // Args + R0 typing handled bespoke in `transfer_helper_call`;
        // proto only needs to admit the call shape.
        constants::BPF_KPTR_XCHG => CallProto::with_args([
            Anything, // R1: &map_value->kptr_field (or &owned_kptr->inner_kptr)
            Anything, // R2: kptr or NULL
            DontCare, DontCare, DontCare,
        ]),

        // ============================================================
        // Helper proto enumeration follow-up (post-batch-3 triage):
        // two helpers surfaced as still-FR on the post-batch-3 sweep
        // but trivially mirror existing kernel protos.
        // ============================================================

        // bpf_skc_to_tcp_timewait_sock(sock_common) -> tcp_timewait_sock_or_null.
        // R0 typing for the timewait variant already wired in
        // `update_call_types` alongside the other skc_to_* helpers.
        constants::BPF_SKC_TO_TCP_TIMEWAIT_SOCK => CallProto::with_args([
            PtrToBTFIdSockCommon, // R1: sock_common
            DontCare, DontCare, DontCare, DontCare,
        ]),

        // bpf_seq_printf_btf(seq, btf_ptr, ptr_size, flags) -> int.
        // Kernel proto (kernel/trace/bpf_trace.c bpf_seq_printf_btf_proto):
        // arg1=PTR_TO_BTF_ID(seq_file), arg2=PTR_TO_MEM|MEM_RDONLY,
        // arg3=CONST_SIZE_OR_ZERO, arg4=ANYTHING.
        constants::BPF_SEQ_PRINTF_BTF => CallProto::with_args([
            PtrToBtfIdNamed { type_name: "seq_file" }, // R1: seq
            PtrToMem,                                  // R2: btf_ptr (rdonly)
            ConstSizeOrZero,                           // R3: ptr_size
            Anything,                                  // R4: flags
            DontCare,
        ])
        .mem_size_pairs(&pairs::SEQ_WRITE)
        .ret(RetKind::Scalar),

        _ => return None,
    })
}

#[allow(dead_code)] // kernel bpf_fastcall pattern id-list; reg-clobber use removed (unfaithful)
pub(crate) fn is_fastcall_helper(helper: u32) -> bool {
    matches!(
        helper,
        constants::BPF_KTIME_GET_NS
            | constants::BPF_GET_SMP_PROCESSOR_ID
            | constants::BPF_GET_CURRENT_PID_TGID
            | constants::BPF_GET_CURRENT_UID_GID
            | constants::BPF_GET_CURRENT_COMM
            | constants::BPF_GET_CURRENT_TASK
            | constants::BPF_GET_NUMA_NODE_ID
            | constants::BPF_GET_CURRENT_CGROUP_ID
            | constants::BPF_JIFFIES64
            | constants::BPF_KTIME_GET_BOOT_NS
            | constants::BPF_KTIME_GET_COARSE_NS
    )
}

/// Returns true if the helper rejects packet pointers for the given argument index.
pub(crate) fn helper_rejects_packet_for_arg(helper: u32, arg_index: usize) -> bool {
    match helper {
        // bpf_skb_store_bytes: R3 (from buffer) cannot be packet pointer
        // because the helper modifies packet data, causing pointer invalidation
        constants::BPF_SKB_STORE_BYTES => arg_index == 2,

        // Add other helpers with similar restrictions here
        _ => false,
    }
}

/// For helpers with PTR_OR_NULL args, returns the index of the paired size argument.
pub(crate) fn get_nullable_ptr_size_pair(helper: u32, ptr_arg_index: usize) -> Option<usize> {
    match helper {
        // bpf_csum_diff: R1=from (PTR_OR_NULL) paired with R2=from_size,
        //                R3=to (PTR_OR_NULL) paired with R4=to_size
        constants::BPF_CSUM_DIFF => match ptr_arg_index {
            0 => Some(1), // R1's size is R2
            2 => Some(3), // R3's size is R4
            _ => None,
        },
        // bpf_snprintf: R1=buf (UNINIT_MEM_OR_NULL) paired with R2=size,
        //               R4=data (MEM_OR_NULL) paired with R5=data_len.
        constants::BPF_SNPRINTF => match ptr_arg_index {
            0 => Some(1),
            3 => Some(4),
            _ => None,
        },
        // bpf_redirect_neigh: R2=params (MEM|MAYBE_NULL) paired with
        // R3=plen (CONST_SIZE_OR_ZERO).
        constants::BPF_REDIRECT_NEIGH => match ptr_arg_index {
            1 => Some(2),
            _ => None,
        },
        // bpf_trace_vprintk: R3=data (MEM|MAYBE_NULL) paired with
        // R4=data_len (CONST_SIZE_OR_ZERO).
        constants::BPF_TRACE_VPRINTK => match ptr_arg_index {
            2 => Some(3),
            _ => None,
        },
        // Add other helpers with PTR_OR_NULL + SIZE_OR_ZERO pairs
        _ => None,
    }
}
