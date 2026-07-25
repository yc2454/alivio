#![allow(dead_code)]

// src/analysis/constants.rs

// ============================================================================
// Basics
// ============================================================================
pub const BPF_STACK_MIN: i64 = -512;
pub const BPF_STACK_MAX: i64 = 0;
pub const BPF_MAX_CALL_FRAMES: usize = 8;

// ============================================================================
// BPF Helper IDs (from linux/bpf.h)
// ============================================================================

pub const BPF_UNSPEC: u32 = 0;
pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
pub const BPF_MAP_LOOKUP_PERCPU_ELEM: u32 = 195;
pub const BPF_SKC_TO_MPTCP_SOCK: u32 = 196;
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
pub const BPF_MAP_DELETE_ELEM: u32 = 3;
pub const BPF_PROBE_READ: u32 = 4;
pub const BPF_KTIME_GET_NS: u32 = 5;
pub const BPF_TRACE_PRINTK: u32 = 6;
pub const BPF_GET_PRANDOM_U32: u32 = 7;
pub const BPF_GET_SMP_PROCESSOR_ID: u32 = 8;
pub const BPF_SKB_STORE_BYTES: u32 = 9;
pub const BPF_L3_CSUM_REPLACE: u32 = 10;
pub const BPF_L4_CSUM_REPLACE: u32 = 11;
pub const BPF_TAIL_CALL: u32 = 12;
pub const BPF_CLONE_REDIRECT: u32 = 13;
pub const BPF_GET_CURRENT_PID_TGID: u32 = 14;
pub const BPF_GET_CURRENT_UID_GID: u32 = 15;
pub const BPF_GET_CURRENT_COMM: u32 = 16;
pub const BPF_GET_CGROUP_CLASS_ID: u32 = 17;
pub const BPF_SKB_VLAN_PUSH: u32 = 18;
pub const BPF_SKB_VLAN_POP: u32 = 19;
pub const BPF_SKB_GET_TUNNEL_KEY: u32 = 20;
pub const BPF_SKB_SET_TUNNEL_KEY: u32 = 21;
pub const BPF_PERF_EVENT_READ: u32 = 22;
pub const BPF_REDIRECT: u32 = 23;
pub const BPF_GET_ROUTE_REALM: u32 = 24;
pub const BPF_PERF_EVENT_OUTPUT: u32 = 25;
pub const BPF_SKB_LOAD_BYTES: u32 = 26;
pub const BPF_GET_STACKID: u32 = 27;
pub const BPF_CSUM_DIFF: u32 = 28;
pub const BPF_SKB_GET_TUNNEL_OPT: u32 = 29;
pub const BPF_SKB_SET_TUNNEL_OPT: u32 = 30;
pub const BPF_SKB_CHANGE_PROTO: u32 = 31;
pub const BPF_SKB_CHANGE_TYPE: u32 = 32;
pub const BPF_SKB_UNDER_CGROUP: u32 = 33;
pub const BPF_GET_HASH_RECALC: u32 = 34;
pub const BPF_GET_CURRENT_TASK: u32 = 35;
pub const BPF_PROBE_WRITE_USER: u32 = 36;
pub const BPF_CURRENT_TASK_UNDER_CGROUP: u32 = 37;
pub const BPF_SKB_CHANGE_TAIL: u32 = 38;
pub const BPF_SKB_PULL_DATA: u32 = 39;
pub const BPF_CSUM_UPDATE: u32 = 40;
pub const BPF_SET_HASH_INVALID: u32 = 41;
pub const BPF_GET_NUMA_NODE_ID: u32 = 42;
pub const BPF_SKB_CHANGE_HEAD: u32 = 43;
pub const BPF_XDP_ADJUST_HEAD: u32 = 44;
pub const BPF_PROBE_READ_STR: u32 = 45;
pub const BPF_GET_SOCKET_COOKIE: u32 = 46;
pub const BPF_GET_SOCKET_UID: u32 = 47;
pub const BPF_SET_HASH: u32 = 48;
pub const BPF_SETSOCKOPT: u32 = 49;
pub const BPF_SKB_ADJUST_ROOM: u32 = 50;
pub const BPF_REDIRECT_MAP: u32 = 51;
pub const BPF_SK_REDIRECT_MAP: u32 = 52;
pub const BPF_SOCK_MAP_UPDATE: u32 = 53;
pub const BPF_XDP_ADJUST_META: u32 = 54;
pub const BPF_PERF_EVENT_READ_VALUE: u32 = 55;
pub const BPF_PERF_PROG_READ_VALUE: u32 = 56;
pub const BPF_GET_SOCKOPT: u32 = 57;
pub const BPF_OVERRIDE_RETURN: u32 = 58;
pub const BPF_SOCK_OPS_CB_FLAGS_SET: u32 = 59;
pub const BPF_MSG_REDIRECT_MAP: u32 = 60;
pub const BPF_MSG_APPLY_BYTES: u32 = 61;
pub const BPF_MSG_CORK_BYTES: u32 = 62;
pub const BPF_MSG_PULL_DATA: u32 = 63;
pub const BPF_BIND: u32 = 64;
pub const BPF_XDP_ADJUST_TAIL: u32 = 65;
pub const BPF_SKB_GET_XFRM_STATE: u32 = 66;
pub const BPF_GET_STACK: u32 = 67;
pub const BPF_SKB_LOAD_BYTES_RELATIVE: u32 = 68;
pub const BPF_FIB_LOOKUP: u32 = 69;
pub const BPF_SOCK_HASH_UPDATE: u32 = 70;
pub const BPF_MSG_REDIRECT_HASH: u32 = 71;
pub const BPF_SK_REDIRECT_HASH: u32 = 72;
pub const BPF_LWT_PUSH_ENCAP: u32 = 73;
pub const BPF_LWT_SEG6_STORE_BYTES: u32 = 74;
pub const BPF_LWT_SEG6_ADJUST_SRH: u32 = 75;
pub const BPF_LWT_SEG6_ACTION: u32 = 76;
pub const BPF_RC_REPEAT: u32 = 77;
pub const BPF_RC_KEYDOWN: u32 = 78;
pub const BPF_SKB_CGROUP_ID: u32 = 79;
pub const BPF_GET_CURRENT_CGROUP_ID: u32 = 80;
pub const BPF_GET_LOCAL_STORAGE: u32 = 81;
pub const BPF_SK_SELECT_REUSEPORT: u32 = 82;
pub const BPF_SKB_ANCESTOR_CGROUP_ID: u32 = 83;
pub const BPF_SK_LOOKUP_TCP: u32 = 84;
pub const BPF_SK_LOOKUP_UDP: u32 = 85;
pub const BPF_SK_RELEASE: u32 = 86;
pub const BPF_MAP_PUSH_ELEM: u32 = 87;
pub const BPF_MAP_POP_ELEM: u32 = 88;
pub const BPF_MAP_PEEK_ELEM: u32 = 89;
pub const BPF_MSG_PUSH_DATA: u32 = 90;
pub const BPF_MSG_POP_DATA: u32 = 91;
pub const BPF_RC_POINTER_REL: u32 = 92;
pub const BPF_SPIN_LOCK: u32 = 93;
pub const BPF_SPIN_UNLOCK: u32 = 94;
pub const BPF_SK_FULLSOCK: u32 = 95;
pub const BPF_TCP_SOCK: u32 = 96;
pub const BPF_SKB_ECN_SET_CE: u32 = 97;
pub const BPF_GET_LISTENER_SOCK: u32 = 98;
pub const BPF_SKC_LOOKUP_TCP: u32 = 99;
pub const BPF_TCP_CHECK_SYNCOOKIE: u32 = 100;
pub const BPF_SYSCTL_GET_NAME: u32 = 101;
pub const BPF_SYSCTL_GET_CURRENT_VALUE: u32 = 102;
pub const BPF_SYSCTL_GET_NEW_VALUE: u32 = 103;
pub const BPF_SYSCTL_SET_NEW_VALUE: u32 = 104;
pub const BPF_STRTOL: u32 = 105;
pub const BPF_STRTOUL: u32 = 106;
pub const BPF_SK_STORAGE_GET: u32 = 107;
pub const BPF_SK_STORAGE_DELETE: u32 = 108;
pub const BPF_SEND_SIGNAL: u32 = 109;
pub const BPF_TCP_GEN_SYNCOOKIE: u32 = 110;
pub const BPF_SKB_OUTPUT: u32 = 111;
pub const BPF_PROBE_READ_USER: u32 = 112;
pub const BPF_PROBE_READ_KERNEL: u32 = 113;
pub const BPF_PROBE_READ_USER_STR: u32 = 114;
pub const BPF_PROBE_READ_KERNEL_STR: u32 = 115;
pub const BPF_TCP_SEND_ACK: u32 = 116;
pub const BPF_SEND_SIGNAL_THREAD: u32 = 117;
pub const BPF_JIFFIES64: u32 = 118;
pub const BPF_READ_BRANCH_RECORDS: u32 = 119;
pub const BPF_GET_NS_CURRENT_PID_TGID: u32 = 120;
pub const BPF_XDP_OUTPUT: u32 = 121;
pub const BPF_GET_NETNS_COOKIE: u32 = 122;
pub const BPF_GET_CURRENT_ANCESTOR_CGROUP_ID: u32 = 123;
pub const BPF_SK_ASSIGN: u32 = 124;
pub const BPF_KTIME_GET_BOOT_NS: u32 = 125;
pub const BPF_SEQ_PRINTF: u32 = 126;
pub const BPF_SEQ_WRITE: u32 = 127;
pub const BPF_SK_CGROUP_ID: u32 = 128;
pub const BPF_SK_ANCESTOR_CGROUP_ID: u32 = 129;
pub const BPF_RINGBUF_OUTPUT: u32 = 130;
pub const BPF_RINGBUF_RESERVE: u32 = 131;
pub const BPF_RINGBUF_SUBMIT: u32 = 132;
pub const BPF_RINGBUF_DISCARD: u32 = 133;
pub const BPF_RINGBUF_QUERY: u32 = 134;
pub const BPF_CSUM_LEVEL: u32 = 135;
pub const BPF_SKC_TO_TCP6_SOCK: u32 = 136;
pub const BPF_SKC_TO_TCP_SOCK: u32 = 137;
pub const BPF_SKC_TO_TCP_TIMEWAIT_SOCK: u32 = 138;
pub const BPF_SKC_TO_TCP_REQUEST_SOCK: u32 = 139;
pub const BPF_SKC_TO_UDP6_SOCK: u32 = 140;
pub const BPF_GET_TASK_STACK: u32 = 141;
pub const BPF_INODE_STORAGE_GET: u32 = 145;
pub const BPF_INODE_STORAGE_DELETE: u32 = 146;
pub const BPF_D_PATH: u32 = 147;
pub const BPF_REDIRECT_NEIGH: u32 = 152;
pub const BPF_REDIRECT_PEER: u32 = 155;
pub const BPF_TASK_STORAGE_GET: u32 = 156;
pub const BPF_TASK_STORAGE_DELETE: u32 = 157;
pub const BPF_GET_CURRENT_TASK_BTF: u32 = 158;
pub const BPF_KTIME_GET_COARSE_NS: u32 = 160;
pub const BPF_SOCK_FROM_FILE: u32 = 162;
pub const BPF_TASK_PT_REGS: u32 = 175;
pub const BPF_GET_BRANCH_SNAPSHOT: u32 = 176;
pub const BPF_TRACE_VPRINTK: u32 = 177;
pub const BPF_COPY_FROM_USER_TASK: u32 = 191;
pub const BPF_SKB_SET_TSTAMP: u32 = 192;
pub const BPF_STORE_HDR_OPT: u32 = 143;
pub const BPF_GET_FUNC_ARG: u32 = 183;
pub const BPF_XDP_STORE_BYTES: u32 = 190;
pub const BPF_IMA_FILE_HASH: u32 = 193;
pub const BPF_RESERVE_HDR_OPT: u32 = 144;
pub const BPF_GET_FUNC_RET: u32 = 184;
pub const BPF_CHECK_MTU: u32 = 163;
pub const BPF_COPY_FROM_USER: u32 = 148;
pub const BPF_FOR_EACH_MAP_ELEM: u32 = 164;
pub const BPF_SNPRINTF: u32 = 165;
pub const BPF_TIMER_INIT: u32 = 169;
pub const BPF_TIMER_SET_CALLBACK: u32 = 170;
pub const BPF_TIMER_START: u32 = 171;
pub const BPF_TIMER_CANCEL: u32 = 172;
pub const BPF_SKC_TO_UNIX_SOCK: u32 = 178;
pub const BPF_FIND_VMA: u32 = 180;
pub const BPF_LOOP: u32 = 181;
pub const BPF_STRNCMP: u32 = 182;
pub const BPF_PER_CPU_PTR: u32 = 153;
pub const BPF_THIS_CPU_PTR: u32 = 154;
pub const BPF_KPTR_XCHG: u32 = 194;
pub const BPF_DYNPTR_FROM_MEM: u32 = 197;
pub const BPF_RINGBUF_RESERVE_DYNPTR: u32 = 198;
pub const BPF_RINGBUF_SUBMIT_DYNPTR: u32 = 199;
pub const BPF_RINGBUF_DISCARD_DYNPTR: u32 = 200;
pub const BPF_DYNPTR_READ: u32 = 201;
pub const BPF_DYNPTR_WRITE: u32 = 202;
pub const BPF_DYNPTR_DATA: u32 = 203;
pub const BPF_USER_RINGBUF_DRAIN: u32 = 209;
pub const BPF_CGRP_STORAGE_GET: u32 = 210;
pub const BPF_CGRP_STORAGE_DELETE: u32 = 211;
// Additional helper IDs.
// IDs match `__BPF_FUNC_MAPPER` in `include/uapi/linux/bpf.h` v6.18-rc4.
pub const BPF_LOAD_HDR_OPT: u32 = 142;
pub const BPF_SNPRINTF_BTF: u32 = 149;
pub const BPF_SEQ_PRINTF_BTF: u32 = 150;
pub const BPF_BPRM_OPTS_SET: u32 = 159;
pub const BPF_IMA_INODE_HASH: u32 = 161;
pub const BPF_SYS_BPF: u32 = 166;
pub const BPF_GET_FUNC_IP: u32 = 173;
pub const BPF_GET_ATTACH_COOKIE: u32 = 174;
pub const BPF_GET_FUNC_ARG_CNT: u32 = 185;
pub const BPF_GET_RETVAL: u32 = 186;
pub const BPF_SET_RETVAL: u32 = 187;
pub const BPF_XDP_GET_BUFF_LEN: u32 = 188;
pub const BPF_XDP_LOAD_BYTES: u32 = 189;
pub const BPF_TCP_RAW_GEN_SYNCOOKIE_IPV4: u32 = 204;
pub const BPF_TCP_RAW_GEN_SYNCOOKIE_IPV6: u32 = 205;
pub const BPF_TCP_RAW_CHECK_SYNCOOKIE_IPV4: u32 = 206;
pub const BPF_TCP_RAW_CHECK_SYNCOOKIE_IPV6: u32 = 207;
pub const BPF_KTIME_GET_TAI_NS: u32 = 208;

pub const BPF_KFUNC_CALL_DUMMY: u32 = 213;
pub const BPF_RCU_READ_LOCK: u32 = 217;
pub const BPF_RCU_READ_UNLOCK: u32 = 218;

/// Maximum valid helper ID (used for validation)
pub const BPF_HELPER_MAX: u32 = 218;

// ============================================================================
// Limits & Defaults
// ============================================================================

pub const DEFAULT_MAP_VALUE_SIZE: i64 = 4096;
pub const MAX_INSN_PROCESSED: usize = 1_000_000;
pub const MAX_TAIL_CALL_DEPTH: u32 = 33;
pub const LOG_HEARTBEAT_INTERVAL: usize = 10_000;
pub const MAX_PACKET_OFF: i64 = 0xFFFF;
pub const MAX_VAR_OFF: i64 = 1 << 29;
pub const MAX_ERRNO: i64 = 4095;

// ============================================================================
// BPF Map Types (from linux/bpf.h)
// ============================================================================
pub const BPF_MAP_TYPE_UNSPEC: u32 = 0;
pub const BPF_MAP_TYPE_HASH: u32 = 1;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_PROG_ARRAY: u32 = 3;
pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: u32 = 4;
pub const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
pub const BPF_MAP_TYPE_STACK_TRACE: u32 = 7;
pub const BPF_MAP_TYPE_CGROUP_ARRAY: u32 = 8;
pub const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
pub const BPF_MAP_TYPE_LRU_PERCPU_HASH: u32 = 10;
pub const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
pub const BPF_MAP_TYPE_ARRAY_OF_MAPS: u32 = 12;
pub const BPF_MAP_TYPE_HASH_OF_MAPS: u32 = 13;
pub const BPF_MAP_TYPE_DEVMAP: u32 = 14;
pub const BPF_MAP_TYPE_SOCKMAP: u32 = 15;
pub const BPF_MAP_TYPE_CPUMAP: u32 = 16;
pub const BPF_MAP_TYPE_XSKMAP: u32 = 17;
pub const BPF_MAP_TYPE_SOCKHASH: u32 = 18;
pub const BPF_MAP_TYPE_CGROUP_STORAGE: u32 = 19;
pub const BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: u32 = 20;
pub const BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: u32 = 21;
pub const BPF_MAP_TYPE_QUEUE: u32 = 22;
pub const BPF_MAP_TYPE_STACK: u32 = 23;
pub const BPF_MAP_TYPE_SK_STORAGE: u32 = 24;
pub const BPF_MAP_TYPE_DEVMAP_HASH: u32 = 25;
pub const BPF_MAP_TYPE_STRUCT_OPS: u32 = 26;
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;
pub const BPF_MAP_TYPE_INODE_STORAGE: u32 = 28;
pub const BPF_MAP_TYPE_TASK_STORAGE: u32 = 29;
pub const BPF_MAP_TYPE_BLOOM_FILTER: u32 = 30;
pub const BPF_MAP_TYPE_USER_RINGBUF: u32 = 31;
pub const BPF_MAP_TYPE_CGRP_STORAGE: u32 = 32;
pub const BPF_MAP_TYPE_ARENA: u32 = 33;

// Data section names (for identifying synthetic maps)
pub const DATA_SECTION_RODATA: &str = ".rodata";
pub const DATA_SECTION_DATA: &str = ".data";
pub const DATA_SECTION_BSS: &str = ".bss";

// ELF Section Types
pub const SHT_NOBITS: u32 = 8;

// Map Flags
// Program access permissions
pub const BPF_F_RDONLY_PROG: u32 = 1 << 7; // 0x0080
pub const BPF_F_WRONLY_PROG: u32 = 1 << 8; // 0x0100
pub const BPF_F_RDWR_PROG: u32 = 1 << 9; // 0x0200

// ===========================================================================
// BPF Program Types
// ===========================================================================
pub const BPF_PROG_TYPE_UNSPEC: u32 = 0;
pub const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
pub const BPF_PROG_TYPE_KPROBE: u32 = 2;
pub const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
pub const BPF_PROG_TYPE_SCHED_ACT: u32 = 4;
pub const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;
pub const BPF_PROG_TYPE_XDP: u32 = 6;
pub const BPF_PROG_TYPE_PERF_EVENT: u32 = 7;
pub const BPF_PROG_TYPE_CGROUP_SKB: u32 = 8;
pub const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
pub const BPF_PROG_TYPE_LWT_IN: u32 = 10;
pub const BPF_PROG_TYPE_LWT_OUT: u32 = 11;
pub const BPF_PROG_TYPE_LWT_XMIT: u32 = 12;
pub const BPF_PROG_TYPE_SOCK_OPS: u32 = 13;
pub const BPF_PROG_TYPE_SK_SKB: u32 = 14;
pub const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
pub const BPF_PROG_TYPE_SK_MSG: u32 = 16;
pub const BPF_PROG_TYPE_RAW_TRACEPOINT: u32 = 17;
pub const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
pub const BPF_PROG_TYPE_LWT_SEG6LOCAL: u32 = 19;
pub const BPF_PROG_TYPE_LIRC_MODE2: u32 = 20;
pub const BPF_PROG_TYPE_SK_REUSEPORT: u32 = 21;
pub const BPF_PROG_TYPE_FLOW_DISSECTOR: u32 = 22;
pub const BPF_PROG_TYPE_CGROUP_SYSCTL: u32 = 23;
pub const BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: u32 = 24;
pub const BPF_PROG_TYPE_CGROUP_SOCKOPT: u32 = 25;
pub const BPF_PROG_TYPE_TRACING: u32 = 26;
pub const BPF_PROG_TYPE_STRUCT_OPS: u32 = 27;
pub const BPF_PROG_TYPE_EXT: u32 = 28;
pub const BPF_PROG_TYPE_LSM: u32 = 29;
pub const BPF_PROG_TYPE_SK_LOOKUP: u32 = 30;
pub const BPF_PROG_TYPE_NETFILTER: u32 = 31;

// ==================================================
// BPF Attach types
// ==================================================
pub const BPF_ATTACH_TYPE_UNSPEC: u32 = 0;
pub const BPF_ATTACH_TYPE_NONE: u32 = 1;
pub const BPF_ATTACH_TYPE_SK_SKB: u32 = 2;
pub const BPF_ATTACH_TYPE_SK_MSG: u32 = 3;
pub const BPF_ATTACH_TYPE_SK_REUSEPORT: u32 = 4;
pub const BPF_ATTACH_TYPE_SK_LOOKUP: u32 = 5;
pub const BPF_ATTACH_TYPE_TRACE_RAW_TP: u32 = 24;
pub const BPF_ATTACH_TYPE_TRACE_ITER: u32 = 28;

// ==================================================
// BTF Constants
// ==================================================

pub const BTF_KIND_INT: u8 = 1;
pub const BTF_KIND_STRUCT: u8 = 4;

// ==================================================
// BPF Test flags
// ==================================================
pub const F_NEEDS_EFFICIENT_UNALIGNED_ACCESS: u32 = 1 << 0;
pub const F_LOAD_WITH_STRICT_ALIGNMENT: u32 = 1 << 1;
/// Kernel `BPF_F_TEST_STATE_FREQ` (include/uapi/linux/bpf.h, value `1U
/// << 3`). When set, the kernel's `is_state_visited` flips
/// `force_new_state=true` (verifier.c v6.15 L18998) which makes every
/// processed instruction a state-cache addition point. In alivio we
/// honor the flag by disabling subsumption-hit pruning entirely: every
/// visit is explored independently. This matches the kernel's intended
/// "behavior is undefined" debugging flag and is the load-bearing
/// mechanism behind iters.c::loop_state_deps2 — the deliberate test
/// vector that proves a verifier explores both inner-loop value paths
/// (b=0 with c=-24 and b=1 with c=-25) only fires when state-frequency
/// is forced; otherwise the verifier's standard pruning collapses the
/// distinct paths and misses the unsafe `*(r10 + c)=…` access.
pub const F_TEST_STATE_FREQ: u32 = 1 << 3;

// ==================================================
// BPF ELF Relocation Types
// ==================================================
pub const R_BPF_64_64: u32 = 1; // 64-bit load (ld_imm64) - used for map pointers
pub const R_BPF_64_32: u32 = 10; // 32-bit call (call insn) - used for function calls
