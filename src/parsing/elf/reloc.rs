use anyhow::Result;
use goblin::elf::Elf;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use super::map::load_ksyms;
use super::types::{BpfCallTarget, BpfMapDef, RelocInfo, RelocKind};
use crate::common::constants::{self, R_BPF_64_32, R_BPF_64_64};
use crate::parsing::bpf_insn::RawBpfInsn;

/// Map a kfunc symbol name to a deterministic synthetic btf_id well above any
/// id a real BTF section would assign (real .BTF tables top out in the
/// thousands; clang and the kernel verifier only ever read these ids out of
/// the call insn's `imm` field, so the only constraint is uniqueness within
/// the analysis-context BTF after the runner registers `name → id`).
///
/// FNV-1a 32-bit, biased into [10_000_000, 10_000_000 + 2^28). Collisions
/// across different kfunc names are theoretically possible but vanishingly
/// rare for the < 100 kfunc names registered in `signatures.rs`.
pub fn synthetic_kfunc_btf_id(name: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in name.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    10_000_000u32.wrapping_add(h & 0x0fff_ffff)
}

/// Look up BPF helper ID by name.
/// Returns None if the name is not a known helper.
pub fn helper_id_by_name(name: &str) -> Option<u32> {
    match name {
        "bpf_unspec" => Some(constants::BPF_UNSPEC),
        "bpf_map_lookup_elem" => Some(constants::BPF_MAP_LOOKUP_ELEM),
        "bpf_map_update_elem" => Some(constants::BPF_MAP_UPDATE_ELEM),
        "bpf_map_delete_elem" => Some(constants::BPF_MAP_DELETE_ELEM),
        "bpf_probe_read" => Some(constants::BPF_PROBE_READ),
        "bpf_ktime_get_ns" => Some(constants::BPF_KTIME_GET_NS),
        "bpf_trace_printk" => Some(constants::BPF_TRACE_PRINTK),
        "bpf_get_prandom_u32" => Some(constants::BPF_GET_PRANDOM_U32),
        "bpf_get_smp_processor_id" => Some(constants::BPF_GET_SMP_PROCESSOR_ID),
        "bpf_skb_store_bytes" => Some(constants::BPF_SKB_STORE_BYTES),
        "bpf_l3_csum_replace" => Some(constants::BPF_L3_CSUM_REPLACE),
        "bpf_l4_csum_replace" => Some(constants::BPF_L4_CSUM_REPLACE),
        "bpf_tail_call" => Some(constants::BPF_TAIL_CALL),
        "bpf_clone_redirect" => Some(constants::BPF_CLONE_REDIRECT),
        "bpf_get_current_pid_tgid" => Some(constants::BPF_GET_CURRENT_PID_TGID),
        "bpf_get_current_uid_gid" => Some(constants::BPF_GET_CURRENT_UID_GID),
        "bpf_get_current_comm" => Some(constants::BPF_GET_CURRENT_COMM),
        "bpf_get_cgroup_classid" => Some(constants::BPF_GET_CGROUP_CLASS_ID),
        "bpf_skb_vlan_push" => Some(constants::BPF_SKB_VLAN_PUSH),
        "bpf_skb_vlan_pop" => Some(constants::BPF_SKB_VLAN_POP),
        "bpf_skb_get_tunnel_key" => Some(constants::BPF_SKB_GET_TUNNEL_KEY),
        "bpf_skb_set_tunnel_key" => Some(constants::BPF_SKB_SET_TUNNEL_KEY),
        "bpf_perf_event_read" => Some(constants::BPF_PERF_EVENT_READ),
        "bpf_redirect" => Some(constants::BPF_REDIRECT),
        "bpf_get_route_realm" => Some(constants::BPF_GET_ROUTE_REALM),
        "bpf_perf_event_output" => Some(constants::BPF_PERF_EVENT_OUTPUT),
        "bpf_skb_load_bytes" => Some(constants::BPF_SKB_LOAD_BYTES),
        "bpf_get_stackid" => Some(constants::BPF_GET_STACKID),
        "bpf_csum_diff" => Some(constants::BPF_CSUM_DIFF),
        "bpf_skb_get_tunnel_opt" => Some(constants::BPF_SKB_GET_TUNNEL_OPT),
        "bpf_skb_set_tunnel_opt" => Some(constants::BPF_SKB_SET_TUNNEL_OPT),
        "bpf_skb_change_proto" => Some(constants::BPF_SKB_CHANGE_PROTO),
        "bpf_skb_change_type" => Some(constants::BPF_SKB_CHANGE_TYPE),
        "bpf_skb_under_cgroup" => Some(constants::BPF_SKB_UNDER_CGROUP),
        "bpf_get_hash_recalc" => Some(constants::BPF_GET_HASH_RECALC),
        "bpf_get_current_task" => Some(constants::BPF_GET_CURRENT_TASK),
        "bpf_probe_write_user" => Some(constants::BPF_PROBE_WRITE_USER),
        "bpf_current_task_under_cgroup" => Some(constants::BPF_CURRENT_TASK_UNDER_CGROUP),
        "bpf_skb_change_tail" => Some(constants::BPF_SKB_CHANGE_TAIL),
        "bpf_skb_pull_data" => Some(constants::BPF_SKB_PULL_DATA),
        "bpf_csum_update" => Some(constants::BPF_CSUM_UPDATE),
        "bpf_set_hash_invalid" => Some(constants::BPF_SET_HASH_INVALID),
        "bpf_get_numa_node_id" => Some(constants::BPF_GET_NUMA_NODE_ID),
        "bpf_skb_change_head" => Some(constants::BPF_SKB_CHANGE_HEAD),
        "bpf_xdp_adjust_head" => Some(constants::BPF_XDP_ADJUST_HEAD),
        "bpf_probe_read_str" => Some(constants::BPF_PROBE_READ_STR),
        "bpf_get_socket_cookie" => Some(constants::BPF_GET_SOCKET_COOKIE),
        "bpf_get_socket_uid" => Some(constants::BPF_GET_SOCKET_UID),
        "bpf_set_hash" => Some(constants::BPF_SET_HASH),
        "bpf_setsockopt" => Some(constants::BPF_SETSOCKOPT),
        "bpf_skb_adjust_room" => Some(constants::BPF_SKB_ADJUST_ROOM),
        "bpf_redirect_map" => Some(constants::BPF_REDIRECT_MAP),
        "bpf_sk_redirect_map" => Some(constants::BPF_SK_REDIRECT_MAP),
        "bpf_sock_map_update" => Some(constants::BPF_SOCK_MAP_UPDATE),
        "bpf_xdp_adjust_meta" => Some(constants::BPF_XDP_ADJUST_META),
        "bpf_perf_event_read_value" => Some(constants::BPF_PERF_EVENT_READ_VALUE),
        "bpf_perf_prog_read_value" => Some(constants::BPF_PERF_PROG_READ_VALUE),
        "bpf_getsockopt" => Some(constants::BPF_GET_SOCKOPT),
        "bpf_override_return" => Some(constants::BPF_OVERRIDE_RETURN),
        "bpf_sock_ops_cb_flags_set" => Some(constants::BPF_SOCK_OPS_CB_FLAGS_SET),
        "bpf_msg_redirect_map" => Some(constants::BPF_MSG_REDIRECT_MAP),
        "bpf_msg_apply_bytes" => Some(constants::BPF_MSG_APPLY_BYTES),
        "bpf_msg_cork_bytes" => Some(constants::BPF_MSG_CORK_BYTES),
        "bpf_msg_pull_data" => Some(constants::BPF_MSG_PULL_DATA),
        "bpf_bind" => Some(constants::BPF_BIND),
        "bpf_xdp_adjust_tail" => Some(constants::BPF_XDP_ADJUST_TAIL),
        "bpf_skb_get_xfrm_state" => Some(constants::BPF_SKB_GET_XFRM_STATE),
        "bpf_get_stack" => Some(constants::BPF_GET_STACK),
        "bpf_skb_load_bytes_relative" => Some(constants::BPF_SKB_LOAD_BYTES_RELATIVE),
        "bpf_fib_lookup" => Some(constants::BPF_FIB_LOOKUP),
        "bpf_sock_hash_update" => Some(constants::BPF_SOCK_HASH_UPDATE),
        "bpf_msg_redirect_hash" => Some(constants::BPF_MSG_REDIRECT_HASH),
        "bpf_sk_redirect_hash" => Some(constants::BPF_SK_REDIRECT_HASH),
        "bpf_lwt_push_encap" => Some(constants::BPF_LWT_PUSH_ENCAP),
        "bpf_lwt_seg6_store_bytes" => Some(constants::BPF_LWT_SEG6_STORE_BYTES),
        "bpf_lwt_seg6_adjust_srh" => Some(constants::BPF_LWT_SEG6_ADJUST_SRH),
        "bpf_lwt_seg6_action" => Some(constants::BPF_LWT_SEG6_ACTION),
        "bpf_rc_repeat" => Some(constants::BPF_RC_REPEAT),
        "bpf_rc_keydown" => Some(constants::BPF_RC_KEYDOWN),
        "bpf_skb_cgroup_id" => Some(constants::BPF_SKB_CGROUP_ID),
        "bpf_get_current_cgroup_id" => Some(constants::BPF_GET_CURRENT_CGROUP_ID),
        "bpf_get_local_storage" => Some(constants::BPF_GET_LOCAL_STORAGE),
        "bpf_sk_select_reuseport" => Some(constants::BPF_SK_SELECT_REUSEPORT),
        "bpf_skb_ancestor_cgroup_id" => Some(constants::BPF_SKB_ANCESTOR_CGROUP_ID),
        "bpf_sk_lookup_tcp" => Some(constants::BPF_SK_LOOKUP_TCP),
        "bpf_sk_lookup_udp" => Some(constants::BPF_SK_LOOKUP_UDP),
        "bpf_sk_release" => Some(constants::BPF_SK_RELEASE),
        "bpf_map_push_elem" => Some(constants::BPF_MAP_PUSH_ELEM),
        "bpf_map_pop_elem" => Some(constants::BPF_MAP_POP_ELEM),
        "bpf_map_peek_elem" => Some(constants::BPF_MAP_PEEK_ELEM),
        "bpf_msg_push_data" => Some(constants::BPF_MSG_PUSH_DATA),
        "bpf_msg_pop_data" => Some(constants::BPF_MSG_POP_DATA),
        "bpf_rc_pointer_rel" => Some(constants::BPF_RC_POINTER_REL),
        "bpf_spin_lock" => Some(constants::BPF_SPIN_LOCK),
        "bpf_spin_unlock" => Some(constants::BPF_SPIN_UNLOCK),
        "bpf_sk_fullsock" => Some(constants::BPF_SK_FULLSOCK),
        "bpf_tcp_sock" => Some(constants::BPF_TCP_SOCK),
        "bpf_skb_ecn_set_ce" => Some(constants::BPF_SKB_ECN_SET_CE),
        "bpf_get_listener_sock" => Some(constants::BPF_GET_LISTENER_SOCK),
        "bpf_skc_lookup_tcp" => Some(constants::BPF_SKC_LOOKUP_TCP),
        "bpf_tcp_check_syncookie" => Some(constants::BPF_TCP_CHECK_SYNCOOKIE),
        "bpf_sysctl_get_name" => Some(constants::BPF_SYSCTL_GET_NAME),
        "bpf_sysctl_get_current_value" => Some(constants::BPF_SYSCTL_GET_CURRENT_VALUE),
        "bpf_sysctl_get_new_value" => Some(constants::BPF_SYSCTL_GET_NEW_VALUE),
        "bpf_sysctl_set_new_value" => Some(constants::BPF_SYSCTL_SET_NEW_VALUE),
        "bpf_strtol" => Some(constants::BPF_STRTOL),
        "bpf_strtoul" => Some(constants::BPF_STRTOUL),
        "bpf_sk_storage_get" => Some(constants::BPF_SK_STORAGE_GET),
        "bpf_sk_storage_delete" => Some(constants::BPF_SK_STORAGE_DELETE),
        "bpf_send_signal" => Some(constants::BPF_SEND_SIGNAL),
        "bpf_tcp_gen_syncookie" => Some(constants::BPF_TCP_GEN_SYNCOOKIE),
        "bpf_skb_output" => Some(constants::BPF_SKB_OUTPUT),
        "bpf_probe_read_user" => Some(constants::BPF_PROBE_READ_USER),
        "bpf_probe_read_kernel" => Some(constants::BPF_PROBE_READ_KERNEL),
        "bpf_probe_read_user_str" => Some(constants::BPF_PROBE_READ_USER_STR),
        "bpf_probe_read_kernel_str" => Some(constants::BPF_PROBE_READ_KERNEL_STR),
        "bpf_tcp_send_ack" => Some(constants::BPF_TCP_SEND_ACK),
        "bpf_send_signal_thread" => Some(constants::BPF_SEND_SIGNAL_THREAD),
        "bpf_jiffies64" => Some(constants::BPF_JIFFIES64),
        "bpf_read_branch_records" => Some(constants::BPF_READ_BRANCH_RECORDS),
        "bpf_get_ns_current_pid_tgid" => Some(constants::BPF_GET_NS_CURRENT_PID_TGID),
        "bpf_xdp_output" => Some(constants::BPF_XDP_OUTPUT),
        "bpf_get_netns_cookie" => Some(constants::BPF_GET_NETNS_COOKIE),
        "bpf_get_current_ancestor_cgroup_id" => Some(constants::BPF_GET_CURRENT_ANCESTOR_CGROUP_ID),
        "bpf_sk_assign" => Some(constants::BPF_SK_ASSIGN),
        "bpf_ktime_get_boot_ns" => Some(constants::BPF_KTIME_GET_BOOT_NS),
        "bpf_seq_printf" => Some(constants::BPF_SEQ_PRINTF),
        "bpf_seq_write" => Some(constants::BPF_SEQ_WRITE),
        "bpf_sk_cgroup_id" => Some(constants::BPF_SK_CGROUP_ID),
        "bpf_sk_ancestor_cgroup_id" => Some(constants::BPF_SK_ANCESTOR_CGROUP_ID),
        "bpf_ringbuf_output" => Some(constants::BPF_RINGBUF_OUTPUT),
        "bpf_ringbuf_reserve" => Some(constants::BPF_RINGBUF_RESERVE),
        "bpf_ringbuf_submit" => Some(constants::BPF_RINGBUF_SUBMIT),
        "bpf_ringbuf_discard" => Some(constants::BPF_RINGBUF_DISCARD),
        "bpf_ringbuf_query" => Some(constants::BPF_RINGBUF_QUERY),
        "bpf_csum_level" => Some(constants::BPF_CSUM_LEVEL),
        "bpf_skc_to_tcp6_sock" => Some(constants::BPF_SKC_TO_TCP6_SOCK),
        "bpf_skc_to_tcp_sock" => Some(constants::BPF_SKC_TO_TCP_SOCK),
        "bpf_skc_to_tcp_timewait_sock" => Some(constants::BPF_SKC_TO_TCP_TIMEWAIT_SOCK),
        "bpf_skc_to_tcp_request_sock" => Some(constants::BPF_SKC_TO_TCP_REQUEST_SOCK),
        "bpf_skc_to_udp6_sock" => Some(constants::BPF_SKC_TO_UDP6_SOCK),
        "bpf_get_task_stack" => Some(constants::BPF_GET_TASK_STACK),
        "bpf_d_path" => Some(constants::BPF_D_PATH),
        "bpf_skc_to_unix_sock" => Some(constants::BPF_SKC_TO_UNIX_SOCK),
        "bpf_user_ringbuf_drain" => Some(constants::BPF_USER_RINGBUF_DRAIN),
        "bpf_dynptr_from_mem" => Some(constants::BPF_DYNPTR_FROM_MEM),
        "bpf_ringbuf_reserve_dynptr" => Some(constants::BPF_RINGBUF_RESERVE_DYNPTR),
        "bpf_ringbuf_submit_dynptr" => Some(constants::BPF_RINGBUF_SUBMIT_DYNPTR),
        "bpf_ringbuf_discard_dynptr" => Some(constants::BPF_RINGBUF_DISCARD_DYNPTR),
        "bpf_dynptr_read" => Some(constants::BPF_DYNPTR_READ),
        "bpf_dynptr_write" => Some(constants::BPF_DYNPTR_WRITE),
        "bpf_dynptr_data" => Some(constants::BPF_DYNPTR_DATA),
        "bpf_sock_from_file" => Some(constants::BPF_SOCK_FROM_FILE),
        "bpf_task_pt_regs" => Some(constants::BPF_TASK_PT_REGS),
        "bpf_copy_from_user_task" => Some(constants::BPF_COPY_FROM_USER_TASK),
        _ => None,
    }
}

pub fn load_relocations<P: AsRef<Path>>(
    path: P,
    maps: &[BpfMapDef],
    target_section_name: &str,
) -> Result<HashMap<usize, RelocInfo>> {
    let path_ref = path.as_ref();
    let ksyms = load_ksyms(path_ref).unwrap_or_default();
    let ksym_to_info: HashMap<&str, (Option<String>, bool)> = ksyms
        .iter()
        .map(|k| (k.name.as_str(), (k.struct_name.clone(), k.is_percpu)))
        .collect();
    let buf = fs::read(path_ref)?;
    let elf = Elf::parse(&buf)?;
    let mut pc_to_reloc = HashMap::new();

    let mut map_name_to_idx: HashMap<&str, usize> = HashMap::new();
    for (i, m) in maps.iter().enumerate() {
        map_name_to_idx.insert(m.name.as_str(), i);
    }

    // Extern variables backed by libbpf-managed maps (today only `.kconfig`).
    // For each, the synthesized map carries the (extern_name, offset) pairs;
    // a `R_BPF_64_64` against a UND extern symbol with one of these names
    // becomes a `MapValue` reloc into this map.
    let mut extern_var_to_loc: HashMap<&str, (usize, i64)> = HashMap::new();
    for (i, m) in maps.iter().enumerate() {
        for (name, off) in &m.extern_var_offsets {
            extern_var_to_loc.insert(name.as_str(), (i, *off as i64));
        }
    }

    let mut section_idx_to_map_idx: HashMap<usize, usize> = HashMap::new();
    for (sec_idx, sh) in elf.section_headers.iter().enumerate() {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name)
            && let Some(&map_idx) = map_name_to_idx.get(name)
        {
            section_idx_to_map_idx.insert(sec_idx, map_idx);
        }
    }

    let target_sec_idx = elf
        .section_headers
        .iter()
        .enumerate()
        .find(|(_, sh)| elf.shdr_strtab.get_at(sh.sh_name) == Some(target_section_name))
        .map(|(i, _)| i)
        .ok_or_else(|| anyhow::anyhow!("Section '{}' not found", target_section_name))?;

    for (reloc_sec_idx, section_relocs) in elf.shdr_relocs.iter() {
        let sh = &elf.section_headers[*reloc_sec_idx];
        if sh.sh_info as usize != target_sec_idx {
            continue;
        }

        for reloc in section_relocs {
            let pc = (reloc.r_offset / 8) as usize;
            let sym = match elf.syms.get(reloc.r_sym) {
                Some(s) => s,
                None => {
                    continue;
                }
            };
            let mut name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();

            let mut r_type = reloc.r_type;
            if r_type == 0 {
                let target_sh_offset = elf.section_headers[target_sec_idx].sh_offset as usize;
                let insn_offset = target_sh_offset + reloc.r_offset as usize;
                if insn_offset < buf.len() {
                    let opcode = buf[insn_offset];
                    if opcode == 0x85 {
                        r_type = R_BPF_64_32;
                    } else if opcode == 0x18 {
                        r_type = R_BPF_64_64;
                    }
                }
            }

            // section-symbol BPF-to-BPF call relocation. clang emits
            // `call <static __noinline subprog in .text>` as an
            // R_BPF_64_32 reloc against the section's STT_SECTION symbol
            // (name == "" or ".text") instead of the function symbol —
            // the callsite's `imm` field carries the PC-relative offset
            // (in 8-byte insn units) to the callee within the referenced
            // section. Resolve by finding the function symbol at that
            // offset, so the name-keyed dispatch below routes to the
            // BpfCall branch instead of the dummy-helper fallback. Same
            // logic as `load_relocations_for_function` below.
            if let Some(resolved) = resolve_section_symbol_call_name(
                &elf,
                &buf,
                &sym,
                &name,
                r_type,
                target_sec_idx,
                reloc.r_offset,
            ) {
                name = resolved;
            }
            let name = name.as_str();

            // Check relocation type
            if r_type == R_BPF_64_32 {
                // Function call relocation - could be helper or BPF-to-BPF
                if let Some(helper_id) = helper_id_by_name(name) {
                    pc_to_reloc.insert(
                        pc,
                        RelocInfo {
                            map_idx: 0,
                            offset: 0,
                            helper_id,
                            kind: RelocKind::HelperCall,
                            bpf_call_target: None,
                            kfunc_name: None,
                            ..Default::default()
                        },
                    );
                } else if let Some((sec_name, offset, size)) =
                    resolve_symbol_location(&elf, &buf, name)
                {
                    // BPF-to-BPF call
                    pc_to_reloc.insert(
                        pc,
                        RelocInfo {
                            map_idx: 0,
                            offset: 0,
                            helper_id: 0,
                            kind: RelocKind::BpfCall,
                            bpf_call_target: Some(BpfCallTarget {
                                func_name: name.to_string(),
                                section: sec_name,
                                offset_in_section: offset,
                                size,
                            }),
                            kfunc_name: None,
                            ..Default::default()
                        },
                    );
                } else if !name.is_empty() {
                    // Recognized kfunc — route through the kfunc dispatcher
                    // by synthesizing a btf_id that the runner will register
                    // into ctx.btf prior to analysis.
                    pc_to_reloc.insert(
                        pc,
                        RelocInfo {
                            map_idx: 0,
                            offset: 0,
                            helper_id: synthetic_kfunc_btf_id(name),
                            kind: RelocKind::KfuncCall,
                            bpf_call_target: None,
                            kfunc_name: Some(name.to_string()),
                            ..Default::default()
                        },
                    );
                } else {
                    // Unknown external function call — fall back to the dummy
                    // helper id so downstream rejection has a stable shape.
                    pc_to_reloc.insert(
                        pc,
                        RelocInfo {
                            map_idx: 0,
                            offset: 0,
                            helper_id: constants::BPF_KFUNC_CALL_DUMMY,
                            kind: RelocKind::HelperCall,
                            bpf_call_target: None,
                            kfunc_name: None,
                            ..Default::default()
                        },
                    );
                }
            } else if r_type == R_BPF_64_64 {
                // Map pointer/value relocation
                if let Some(&map_idx) = map_name_to_idx.get(name) {
                    pc_to_reloc.insert(
                        pc,
                        RelocInfo {
                            map_idx,
                            offset: 0,
                            helper_id: 0,
                            kind: RelocKind::MapPtr,
                            bpf_call_target: None,
                            kfunc_name: None,
                            ..Default::default()
                        },
                    );
                } else if let Some(&map_idx) = section_idx_to_map_idx.get(&sym.st_shndx) {
                    pc_to_reloc.insert(
                        pc,
                        RelocInfo {
                            map_idx,
                            offset: sym.st_value as i64,
                            helper_id: 0,
                            kind: RelocKind::MapValue,
                            bpf_call_target: None,
                            kfunc_name: None,
                            ..Default::default()
                        },
                    );
                } else if let Some(&(map_idx, offset)) = extern_var_to_loc.get(name) {
                    // libbpf-managed extern (e.g. `.kconfig` `__kconfig` var).
                    // Symbol is UND in the ELF; the synthesized map carries
                    // the in-value offset.
                    pc_to_reloc.insert(
                        pc,
                        RelocInfo {
                            map_idx,
                            offset,
                            helper_id: 0,
                            kind: RelocKind::MapValue,
                            bpf_call_target: None,
                            kfunc_name: None,
                            ..Default::default()
                        },
                    );
                } else if let Some((struct_name, is_percpu)) = ksym_to_info.get(name).cloned() {
                    // `__ksym` extern: kernel resolves at load time via
                    // `BPF_PSEUDO_BTF_ID`. Lowerer + transfer consume
                    // `ksym_struct_name`/`ksym_is_percpu` to materialize a
                    // typed `PtrToBtfId{flags: TRUSTED|MEM_RDONLY[|PERCPU]}`
                    // (struct ksyms) or scalar address (typeless).
                    pc_to_reloc.insert(
                        pc,
                        RelocInfo {
                            kind: RelocKind::Ksym,
                            ksym_struct_name: struct_name,
                            ksym_is_percpu: is_percpu,
                            ..Default::default()
                        },
                    );
                } else {
                    // PSEUDO_FUNC: callback-subprog pointer baked into an
                    // LD_IMM64. Symbol is either the callee directly or
                    // the section symbol with the byte offset stored in
                    // the LD_IMM64's own imm field.
                    let host_sh_offset = elf.section_headers[target_sec_idx].sh_offset as usize;
                    let insn_file_offset = host_sh_offset + reloc.r_offset as usize;
                    if let Some((fn_name, sec_name, off, size)) =
                        resolve_pseudo_func_target(&elf, &buf, &sym, name, insn_file_offset)
                    {
                        pc_to_reloc.insert(
                            pc,
                            RelocInfo {
                                map_idx: 0,
                                offset: 0,
                                helper_id: 0,
                                kind: RelocKind::PseudoFunc,
                                bpf_call_target: Some(BpfCallTarget {
                                    func_name: fn_name,
                                    section: sec_name,
                                    offset_in_section: off,
                                    size,
                                }),
                                kfunc_name: None,
                                ..Default::default()
                            },
                        );
                    }
                }
            }
        }
    }
    Ok(pc_to_reloc)
}

/// Resolve a section-symbol BPF-to-BPF call relocation to the actual
/// function name at the call target. Returns `None` when the reloc is
/// not a section-symbol call (so the caller leaves `name` untouched).
///
/// clang emits `call <static __noinline subprog in .text>` as an
/// `R_BPF_64_32` reloc against the `.text` STT_SECTION symbol (name ==
/// "" or starts with `.`). The callsite's `imm` field carries the
/// PC-relative offset (in 8-byte insn units) to the callee within the
/// referenced section. We resolve by locating the function symbol at
/// that byte offset so the downstream name-keyed dispatch routes to
/// `RelocKind::BpfCall` instead of the dummy-helper fallback (which
/// would otherwise produce a spurious "Invalid helper ID" reject).
fn resolve_section_symbol_call_name(
    elf: &Elf,
    buf: &[u8],
    sym: &goblin::elf::Sym,
    current_name: &str,
    r_type: u32,
    host_sec_idx: usize,
    r_offset: u64,
) -> Option<String> {
    if r_type != R_BPF_64_32 {
        return None;
    }
    if sym.st_shndx >= elf.section_headers.len() {
        return None;
    }
    let is_section_symbol = sym.st_type() == goblin::elf::sym::STT_SECTION
        || current_name.is_empty()
        || current_name.starts_with('.');
    if !is_section_symbol {
        return None;
    }
    if helper_id_by_name(current_name).is_some() {
        return None;
    }
    let target_sec_idx_resolved = sym.st_shndx;
    let host_sh = &elf.section_headers[host_sec_idx];
    let host_sh_offset = host_sh.sh_offset as usize;
    let insn_offset = host_sh_offset + r_offset as usize;
    if insn_offset + 8 > buf.len() {
        return None;
    }
    let imm_off_bytes = &buf[insn_offset + 4..insn_offset + 8];
    let imm = i32::from_le_bytes(imm_off_bytes.try_into().ok()?);
    let target_byte_off = if target_sec_idx_resolved == host_sec_idx {
        r_offset as i64 + 8 + (imm as i64) * 8
    } else {
        // Cross-section: section symbol's st_value is the anchor,
        // imm encodes 8-byte-unit offset from "next insn".
        sym.st_value as i64 + (imm as i64 + 1) * 8
    };
    // Prefer STT_FUNC over STT_NOTYPE labels at the same offset.
    let mut best: Option<&str> = None;
    let mut best_is_func = false;
    for s in elf.syms.iter() {
        let st_type = s.st_type();
        let func_like =
            st_type == goblin::elf::sym::STT_FUNC || st_type == goblin::elf::sym::STT_NOTYPE;
        if !func_like {
            continue;
        }
        if s.st_shndx != target_sec_idx_resolved {
            continue;
        }
        if s.st_value as i64 != target_byte_off {
            continue;
        }
        let n = elf.strtab.get_at(s.st_name).unwrap_or("");
        if n.is_empty() || n.starts_with('.') {
            continue;
        }
        let is_func = st_type == goblin::elf::sym::STT_FUNC;
        if best.is_none() || (is_func && !best_is_func) {
            best = Some(n);
            best_is_func = is_func;
        }
    }
    best.map(|s| s.to_string())
}

/// Resolve a `R_BPF_64_64` against an executable section as a callback
/// function pointer (`BPF_PSEUDO_FUNC`). Returns the (function name,
/// section name, byte offset within section, size) the LD_IMM64 should
/// resolve to, or `None` if the symbol doesn't point at a function in an
/// executable section.
///
/// Two clang-emitted shapes are handled:
/// - Function symbol (`STT_FUNC`) directly naming the callback subprog.
/// - Section symbol (`STT_SECTION`, name `.text`/empty) — the LD_IMM64's
///   own low-imm carries the byte offset of the target within the
///   section. We read it back from `buf` and look up the function symbol
///   at that offset.
fn resolve_pseudo_func_target(
    elf: &Elf,
    buf: &[u8],
    sym: &goblin::elf::Sym,
    sym_name: &str,
    insn_file_offset: usize,
) -> Option<(String, String, usize, usize)> {
    use goblin::elf::sym::{STT_FUNC, STT_NOTYPE, STT_SECTION};
    const SHF_EXECINSTR: u64 = 0x4;

    if sym.st_shndx >= elf.section_headers.len() {
        return None;
    }
    let target_sh = &elf.section_headers[sym.st_shndx];
    if target_sh.sh_flags & SHF_EXECINSTR == 0 {
        return None;
    }
    let target_sec_name = elf.shdr_strtab.get_at(target_sh.sh_name)?.to_string();

    // Direct function symbol.
    if sym.st_type() == STT_FUNC && !sym_name.is_empty() && !sym_name.starts_with('.') {
        return Some((
            sym_name.to_string(),
            target_sec_name,
            sym.st_value as usize,
            sym.st_size as usize,
        ));
    }

    // Section symbol — read the LD_IMM64's existing low-imm to get the
    // byte offset of the callee within the referenced section. Insn is
    // 8 bytes (code/regs/off/imm); imm starts at byte 4 (LE).
    if sym.st_type() == STT_SECTION || sym_name.is_empty() || sym_name.starts_with('.') {
        if insn_file_offset + 8 > buf.len() {
            return None;
        }
        let imm_bytes = &buf[insn_file_offset + 4..insn_file_offset + 8];
        let imm = i32::from_le_bytes(imm_bytes.try_into().ok()?);
        let target_byte_off = sym.st_value as usize + imm as usize;

        for s in elf.syms.iter() {
            let st_type = s.st_type();
            if st_type != STT_FUNC && st_type != STT_NOTYPE {
                continue;
            }
            if s.st_shndx != sym.st_shndx {
                continue;
            }
            if s.st_value as usize != target_byte_off {
                continue;
            }
            let n = elf.strtab.get_at(s.st_name).unwrap_or("");
            if n.is_empty() || n.starts_with('.') {
                continue;
            }
            return Some((
                n.to_string(),
                target_sec_name,
                target_byte_off,
                s.st_size as usize,
            ));
        }
    }
    None
}

/// Resolve a symbol name to its location (section name, offset within section, size).
/// Returns None if the symbol is not found or is not a function symbol in a valid section.
fn resolve_symbol_location(
    elf: &Elf,
    _buf: &[u8],
    symbol_name: &str,
) -> Option<(String, usize, usize)> {
    use goblin::elf::sym::{STT_FUNC, STT_NOTYPE};
    const SHF_EXECINSTR: u64 = 0x4;

    // Find the symbol by name
    for sym in elf.syms.iter() {
        let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
        if name != symbol_name {
            continue;
        }

        // Function symbols are the common case; clang also emits some
        // `static __naked __noinline` BPF subprogs with STT_NOTYPE binding
        // pointing into a code section. Accept either, gated on the target
        // section being executable so we don't accidentally match a data
        // symbol whose name collides with a function.
        let is_func_like = sym.st_type() == STT_FUNC || sym.st_type() == STT_NOTYPE;
        if !is_func_like {
            continue;
        }

        // Get the section name from section index
        if sym.st_shndx >= elf.section_headers.len() {
            continue;
        }

        let sh = &elf.section_headers[sym.st_shndx];
        if sh.sh_flags & SHF_EXECINSTR == 0 {
            continue;
        }
        let sec_name = elf.shdr_strtab.get_at(sh.sh_name)?;

        return Some((
            sec_name.to_string(),
            sym.st_value as usize,
            sym.st_size as usize,
        ));
    }

    None
}

/// Load relocations for a specific function within a section.
/// Adjusts PC values by subtracting the function's byte offset within the section.
pub fn load_relocations_for_function<P: AsRef<Path>>(
    path: P,
    maps: &[BpfMapDef],
    target_section_name: &str,
    func_byte_offset: usize,
    func_byte_size: usize,
) -> Result<HashMap<usize, RelocInfo>> {
    let path_ref = path.as_ref();
    let ksyms = load_ksyms(path_ref).unwrap_or_default();
    let ksym_to_info: HashMap<&str, (Option<String>, bool)> = ksyms
        .iter()
        .map(|k| (k.name.as_str(), (k.struct_name.clone(), k.is_percpu)))
        .collect();
    let buf = fs::read(path_ref)?;
    let elf = Elf::parse(&buf)?;
    let mut pc_to_reloc = HashMap::new();

    let mut map_name_to_idx: HashMap<&str, usize> = HashMap::new();
    for (i, m) in maps.iter().enumerate() {
        map_name_to_idx.insert(m.name.as_str(), i);
    }

    // Extern variables backed by libbpf-managed maps (today only `.kconfig`).
    // For each, the synthesized map carries the (extern_name, offset) pairs;
    // a `R_BPF_64_64` against a UND extern symbol with one of these names
    // becomes a `MapValue` reloc into this map.
    let mut extern_var_to_loc: HashMap<&str, (usize, i64)> = HashMap::new();
    for (i, m) in maps.iter().enumerate() {
        for (name, off) in &m.extern_var_offsets {
            extern_var_to_loc.insert(name.as_str(), (i, *off as i64));
        }
    }

    let mut section_idx_to_map_idx: HashMap<usize, usize> = HashMap::new();
    for (sec_idx, sh) in elf.section_headers.iter().enumerate() {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name)
            && let Some(&map_idx) = map_name_to_idx.get(name)
        {
            section_idx_to_map_idx.insert(sec_idx, map_idx);
        }
    }

    let target_sec_idx = elf
        .section_headers
        .iter()
        .enumerate()
        .find(|(_, sh)| elf.shdr_strtab.get_at(sh.sh_name) == Some(target_section_name))
        .map(|(i, _)| i)
        .ok_or_else(|| anyhow::anyhow!("Section '{}' not found", target_section_name))?;

    // Calculate PC range for this function
    let func_start_pc = func_byte_offset / 8;
    let func_end_pc = (func_byte_offset + func_byte_size) / 8;

    for (reloc_sec_idx, section_relocs) in elf.shdr_relocs.iter() {
        let sh = &elf.section_headers[*reloc_sec_idx];
        if sh.sh_info as usize != target_sec_idx {
            continue;
        }

        for reloc in section_relocs {
            let section_pc = (reloc.r_offset / 8) as usize;

            // Only include relocations within this function's range
            if section_pc < func_start_pc || section_pc >= func_end_pc {
                continue;
            }

            // Adjust PC to be relative to function start
            let func_pc = section_pc - func_start_pc;

            let sym = match elf.syms.get(reloc.r_sym) {
                Some(s) => s,
                None => continue,
            };
            let mut name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();

            let mut r_type = reloc.r_type;
            if r_type == 0 {
                let target_sh_offset = elf.section_headers[target_sec_idx].sh_offset as usize;
                let insn_offset = target_sh_offset + reloc.r_offset as usize;
                if insn_offset < buf.len() {
                    let opcode = buf[insn_offset];
                    if opcode == 0x85 {
                        r_type = R_BPF_64_32;
                    } else if opcode == 0x18 {
                        r_type = R_BPF_64_64;
                    }
                }
            }

            // section-symbol BPF-to-BPF call relocation. clang
            // emits `call <static __noinline subprog in .text>` as an
            // R_BPF_64_32 reloc against the section's STT_SECTION symbol
            // (name == "" or ".text") instead of the function symbol — the
            // callsite's `imm` field carries the PC-relative offset (in
            // 8-byte instruction units) to the callee within the same
            // section. Resolve by finding the function symbol that lives
            // at the destination offset.
            let is_section_symbol = sym.st_type() == goblin::elf::sym::STT_SECTION
                || (r_type == R_BPF_64_32 && (name.is_empty() || name.starts_with('.')));
            if r_type == R_BPF_64_32
                && is_section_symbol
                && sym.st_shndx < elf.section_headers.len()
                && helper_id_by_name(&name).is_none()
            {
                let target_sec_idx_resolved = sym.st_shndx;
                let host_sh = &elf.section_headers[target_sec_idx];
                let host_sh_offset = host_sh.sh_offset as usize;
                let insn_offset = host_sh_offset + reloc.r_offset as usize;
                if insn_offset + 8 <= buf.len() {
                    // BPF call insn is 8 bytes: code(1) regs(1) off(2) imm(4).
                    let imm_off_bytes = &buf[insn_offset + 4..insn_offset + 8];
                    let imm = i32::from_le_bytes(imm_off_bytes.try_into().unwrap());
                    // Target byte offset within the *referenced* section.
                    // The callsite is at byte `reloc.r_offset` within the
                    // host section; the call's imm is in 8-byte insn units
                    // and counts from the next insn (PC+1). Same-section
                    // calls are the typical case; cross-section section-
                    // symbol relocs (e.g. tc -> .text) are also common.
                    let target_byte_off = if target_sec_idx_resolved == target_sec_idx {
                        reloc.r_offset as i64 + 8 + (imm as i64) * 8
                    } else {
                        // Cross-section: imm encodes a relative offset in
                        // 8-byte instruction units from "next insn", same
                        // PC-relative form as same-section calls. With the
                        // section symbol as the anchor (st_value == 0), the
                        // resolved target is at (imm + 1) * 8 bytes in the
                        // referenced section.
                        sym.st_value as i64 + (imm as i64 + 1) * 8
                    };
                    // Prefer STT_FUNC (the actual subprog) over STT_NOTYPE
                    // (labels generated by inline asm `l0_%=:` etc., which
                    // the linker emits as local symbols at the same offset
                    // when the subprog body starts with a labeled block).
                    let mut best: Option<&str> = None;
                    let mut best_is_func = false;
                    for s in elf.syms.iter() {
                        let st_type = s.st_type();
                        let func_like = st_type == goblin::elf::sym::STT_FUNC
                            || st_type == goblin::elf::sym::STT_NOTYPE;
                        if !func_like {
                            continue;
                        }
                        if s.st_shndx != target_sec_idx_resolved {
                            continue;
                        }
                        if s.st_value as i64 != target_byte_off {
                            continue;
                        }
                        let n = elf.strtab.get_at(s.st_name).unwrap_or("");
                        if n.is_empty() || n.starts_with('.') {
                            continue;
                        }
                        let is_func = st_type == goblin::elf::sym::STT_FUNC;
                        if best.is_none() || (is_func && !best_is_func) {
                            best = Some(n);
                            best_is_func = is_func;
                        }
                    }
                    if let Some(n) = best {
                        name = n.to_string();
                    }
                }
            }
            let name = name.as_str();

            // Check relocation type
            if r_type == R_BPF_64_32 {
                // Function call relocation - could be helper or BPF-to-BPF
                if let Some(helper_id) = helper_id_by_name(name) {
                    pc_to_reloc.insert(
                        func_pc,
                        RelocInfo {
                            map_idx: 0,
                            offset: 0,
                            helper_id,
                            kind: RelocKind::HelperCall,
                            bpf_call_target: None,
                            kfunc_name: None,
                            ..Default::default()
                        },
                    );
                } else if let Some((sec_name, offset, size)) =
                    resolve_symbol_location(&elf, &buf, name)
                {
                    // BPF-to-BPF call
                    pc_to_reloc.insert(
                        func_pc,
                        RelocInfo {
                            map_idx: 0,
                            offset: 0,
                            helper_id: 0,
                            kind: RelocKind::BpfCall,
                            bpf_call_target: Some(BpfCallTarget {
                                func_name: name.to_string(),
                                section: sec_name,
                                offset_in_section: offset,
                                size,
                            }),
                            kfunc_name: None,
                            ..Default::default()
                        },
                    );
                } else if !name.is_empty() {
                    pc_to_reloc.insert(
                        func_pc,
                        RelocInfo {
                            map_idx: 0,
                            offset: 0,
                            helper_id: synthetic_kfunc_btf_id(name),
                            kind: RelocKind::KfuncCall,
                            bpf_call_target: None,
                            kfunc_name: Some(name.to_string()),
                            ..Default::default()
                        },
                    );
                } else {
                    // Unknown external function call — fall back to the dummy
                    // helper id so downstream rejection has a stable shape.
                    pc_to_reloc.insert(
                        func_pc,
                        RelocInfo {
                            map_idx: 0,
                            offset: 0,
                            helper_id: constants::BPF_KFUNC_CALL_DUMMY,
                            kind: RelocKind::HelperCall,
                            bpf_call_target: None,
                            kfunc_name: None,
                            ..Default::default()
                        },
                    );
                }
            } else if r_type == R_BPF_64_64 {
                // Map pointer/value relocation
                if let Some(&map_idx) = map_name_to_idx.get(name) {
                    pc_to_reloc.insert(
                        func_pc,
                        RelocInfo {
                            map_idx,
                            offset: 0,
                            helper_id: 0,
                            kind: RelocKind::MapPtr,
                            bpf_call_target: None,
                            kfunc_name: None,
                            ..Default::default()
                        },
                    );
                } else if let Some(&map_idx) = section_idx_to_map_idx.get(&sym.st_shndx) {
                    pc_to_reloc.insert(
                        func_pc,
                        RelocInfo {
                            map_idx,
                            offset: sym.st_value as i64,
                            helper_id: 0,
                            kind: RelocKind::MapValue,
                            bpf_call_target: None,
                            kfunc_name: None,
                            ..Default::default()
                        },
                    );
                } else if let Some(&(map_idx, offset)) = extern_var_to_loc.get(name) {
                    // libbpf-managed extern (e.g. `.kconfig` `__kconfig` var).
                    pc_to_reloc.insert(
                        func_pc,
                        RelocInfo {
                            map_idx,
                            offset,
                            helper_id: 0,
                            kind: RelocKind::MapValue,
                            bpf_call_target: None,
                            kfunc_name: None,
                            ..Default::default()
                        },
                    );
                } else if let Some((struct_name, is_percpu)) = ksym_to_info.get(name).cloned() {
                    // `__ksym` extern: BPF_PSEUDO_BTF_ID resolution. See
                    // `load_relocations` for full description.
                    pc_to_reloc.insert(
                        func_pc,
                        RelocInfo {
                            kind: RelocKind::Ksym,
                            ksym_struct_name: struct_name,
                            ksym_is_percpu: is_percpu,
                            ..Default::default()
                        },
                    );
                } else {
                    let host_sh_offset = elf.section_headers[target_sec_idx].sh_offset as usize;
                    let insn_file_offset = host_sh_offset + reloc.r_offset as usize;
                    if let Some((fn_name, sec_name, off, size)) =
                        resolve_pseudo_func_target(&elf, &buf, &sym, name, insn_file_offset)
                    {
                        pc_to_reloc.insert(
                            func_pc,
                            RelocInfo {
                                map_idx: 0,
                                offset: 0,
                                helper_id: 0,
                                kind: RelocKind::PseudoFunc,
                                bpf_call_target: Some(BpfCallTarget {
                                    func_name: fn_name,
                                    section: sec_name,
                                    offset_in_section: off,
                                    size,
                                }),
                                kfunc_name: None,
                                ..Default::default()
                            },
                        );
                    }
                }
            }
        }
    }
    Ok(pc_to_reloc)
}

/// Fix the LD_IMM64 imm pair for every `PseudoFunc` reloc whose callee
/// PC is now known. The lowerer reads the LD_IMM64 as an i64 = (high <<
/// 32) | low (zero-combined), so we sign-extend by setting `cont.imm =
/// -1` for negative offsets and `0` otherwise.
fn fix_pseudo_func_imms(
    insns: &mut [RawBpfInsn],
    relocs: &HashMap<usize, RelocInfo>,
    func_offsets: &HashMap<String, usize>,
) {
    for (&ld_pc, reloc) in relocs.iter() {
        if reloc.kind != RelocKind::PseudoFunc {
            continue;
        }
        let Some(target) = reloc.bpf_call_target.as_ref() else {
            continue;
        };
        let Some(&target_pc) = func_offsets.get(&target.func_name) else {
            continue;
        };
        if ld_pc + 1 >= insns.len() {
            continue;
        }
        let relative = (target_pc as i64) - (ld_pc as i64) - 2;
        let low = relative as i32;
        let high = if relative < 0 { -1 } else { 0 };
        insns[ld_pc].src = 4; // BPF_PSEUDO_FUNC
        insns[ld_pc].imm = low;
        insns[ld_pc + 1].imm = high;
    }
}

/// Patch raw BPF instructions with relocation info.
/// This allows the lowerer (bpf_to_ast) to identify map pointers/values correctly.
pub fn apply_relocs(insns: &mut [RawBpfInsn], pc_to_reloc: &HashMap<usize, RelocInfo>) {
    for (&pc, reloc) in pc_to_reloc {
        if pc < insns.len() {
            let insn = &mut insns[pc];

            match reloc.kind {
                RelocKind::MapPtr | RelocKind::MapValue => {
                    // Must be a BPF_LD_IMM64 instruction (0x18)
                    if insn.code == 0x18 {
                        match reloc.kind {
                            RelocKind::MapPtr => {
                                insn.src = 1;
                                insn.imm = reloc.map_idx as i32;
                            }
                            RelocKind::MapValue => {
                                insn.src = 2;
                                insn.imm = reloc.map_idx as i32;
                                // The offset should be put in the continuation instruction's imm field
                                if pc + 1 < insns.len() {
                                    insns[pc + 1].imm = reloc.offset as i32;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                RelocKind::HelperCall => {
                    // Must be a BPF_CALL instruction (0x85)
                    if insn.code == 0x85 {
                        // Convert from BPF_PSEUDO_CALL (src=1) to standard helper call (src=0)
                        insn.src = 0;
                        insn.imm = reloc.helper_id as i32;
                    }
                }
                RelocKind::BpfCall => {
                    // BPF-to-BPF call - the imm field will be fixed by combine_program_with_subprogs
                    // Here we just ensure src=1 (BPF_PSEUDO_CALL) is set for proper lowering
                    if insn.code == 0x85 {
                        insn.src = 1; // BPF_PSEUDO_CALL
                    }
                }
                RelocKind::KfuncCall => {
                    // BPF_PSEUDO_KFUNC_CALL — the lowerer (bpf_to_ast) emits
                    // `Instr::Call { kind: Kfunc { btf_id, .. } }`, and the
                    // runner registers `kfunc_name → helper_id` into ctx.btf
                    // so the kfunc dispatcher's `btf.kfunc_name(btf_id)`
                    // lookup resolves the name and routes through the proto.
                    if insn.code == 0x85 {
                        insn.src = 2;
                        insn.imm = reloc.helper_id as i32;
                    }
                }
                RelocKind::PseudoFunc => {
                    // src/imm pair are written by `fix_pseudo_func_imms`
                    // once the callee's combined PC is known.
                }
                RelocKind::Ksym => {
                    // `__ksym` extern: encode as `BPF_PSEUDO_BTF_ID`
                    // (LDIMM64 src=3). The kernel's `imm` would be the
                    // kernel BTF id of the symbol; we don't have one
                    // (we don't ship vmlinux BTF), but the lowerer +
                    // transfer routes via the `pc_to_reloc` lookup at
                    // analysis time and reads the resolved struct/percpu
                    // metadata from the reloc info, not from `imm`.
                    if insn.code == 0x18 {
                        insn.src = 3;
                    }
                }
            }
        }
    }
}

/// Discover all BPF-to-BPF call targets for a given section.
pub fn discover_bpf_call_targets<P: AsRef<Path>>(
    path: P,
    target_section_name: &str,
) -> Result<Vec<BpfCallTarget>> {
    let buf = fs::read(&path)?;
    let elf = Elf::parse(&buf)?;
    let mut targets = Vec::new();

    let target_sec_idx = elf
        .section_headers
        .iter()
        .enumerate()
        .find(|(_, sh)| elf.shdr_strtab.get_at(sh.sh_name) == Some(target_section_name))
        .map(|(i, _)| i);

    let target_sec_idx = match target_sec_idx {
        Some(idx) => idx,
        None => return Ok(Vec::new()),
    };

    for (reloc_sec_idx, section_relocs) in elf.shdr_relocs.iter() {
        let sh = &elf.section_headers[*reloc_sec_idx];
        if sh.sh_info as usize != target_sec_idx {
            continue;
        }

        let host_sh_offset = elf.section_headers[target_sec_idx].sh_offset as usize;
        for reloc in section_relocs {
            // Mirror load_relocations' r_type inference: many real-world
            // relocs carry r_type 0 and the relocated insn's opcode
            // decides (0x85 = call → R_BPF_64_32; 0x18 = LD_IMM64 →
            // R_BPF_64_64). Without this, BPF_PSEUDO_FUNC callback
            // ld_imm64s (which are R_BPF_64_64, NOT R_BPF_64_32) would
            // be skipped entirely, so a program whose only
            // cross-section dependency is a `bpf_for_each_map_elem` /
            // `bpf_loop` callback subprog (in `.text`) took the
            // single-section path and never appended the callback —
            // R2 stayed ScalarValue ⇒ "expected PTR_TO_CALLBACK".
            let mut r_type = reloc.r_type;
            let insn_file_offset = host_sh_offset + reloc.r_offset as usize;
            if r_type == 0 && insn_file_offset < buf.len() {
                match buf[insn_file_offset] {
                    0x85 => r_type = R_BPF_64_32,
                    0x18 => r_type = R_BPF_64_64,
                    _ => {}
                }
            }

            let sym = match elf.syms.get(reloc.r_sym) {
                Some(s) => s,
                None => continue,
            };
            let raw_name = elf.strtab.get_at(sym.st_name).unwrap_or("");

            // Skip helper functions
            if helper_id_by_name(raw_name).is_some() {
                continue;
            }

            // Resolve section-symbol cross-section calls (a
            // `kprobe/foo -> .text:<subprog>` call, encoded as
            // R_BPF_64_32 against `.text` STT_SECTION). Without this
            // the dispatch below sees an empty name, resolve_symbol_location
            // returns None, and the cross-section target goes undetected →
            // loader falls back to single-section parsing → subprog body
            // missing → "last insn at pc 0 is not an exit or jmp".
            let resolved_name = resolve_section_symbol_call_name(
                &elf,
                &buf,
                &sym,
                raw_name,
                r_type,
                target_sec_idx,
                reloc.r_offset,
            );
            let name = resolved_name.as_deref().unwrap_or(raw_name);

            if r_type == R_BPF_64_32 {
                // Cross-section BPF-to-BPF call (unchanged behavior).
                if let Some((sec_name, offset, size)) = resolve_symbol_location(&elf, &buf, name)
                    && sec_name != target_section_name
                {
                    targets.push(BpfCallTarget {
                        func_name: name.to_string(),
                        section: sec_name,
                        offset_in_section: offset,
                        size,
                    });
                }
            } else if r_type == R_BPF_64_64 {
                // ADDITIVE: BPF_PSEUDO_FUNC callback subprog pointer
                // baked into an LD_IMM64. resolve_pseudo_func_target
                // returns Some only when the symbol points at a
                // function in an executable section (handles the
                // STT_SECTION `.text`+offset shape clang emits) — map
                // / ksym ld_imm64s resolve to non-exec sections / UND
                // and yield None, so this stays precise.
                if let Some((fn_name, sec_name, off, size)) =
                    resolve_pseudo_func_target(&elf, &buf, &sym, name, insn_file_offset)
                    && sec_name != target_section_name
                {
                    targets.push(BpfCallTarget {
                        func_name: fn_name,
                        section: sec_name,
                        offset_in_section: off,
                        size,
                    });
                }
            }
        }
    }

    // Remove duplicates (same function may be called multiple times)
    targets.sort_by(|a, b| (&a.section, &a.func_name).cmp(&(&b.section, &b.func_name)));
    targets.dedup_by(|a, b| a.func_name == b.func_name && a.section == b.section);

    Ok(targets)
}

/// Combined program with all subprograms appended
#[derive(Debug)]
pub struct CombinedProgram {
    pub raw_insns: Vec<RawBpfInsn>,
    pub pc_to_reloc: HashMap<usize, RelocInfo>,
    /// Maps function name to its start PC in the combined program
    pub func_offsets: HashMap<String, usize>,
}

/// Collect all sections referenced by cross-section calls, transitively.
fn collect_referenced_sections<P: AsRef<Path> + Clone>(
    path: P,
    main_section: &str,
) -> Result<Vec<String>> {
    let mut referenced = Vec::new();
    let mut visited = std::collections::HashSet::new();
    visited.insert(main_section.to_string());

    let mut to_process = vec![main_section.to_string()];

    while let Some(section) = to_process.pop() {
        let targets = discover_bpf_call_targets(&path, &section)?;

        for target in targets {
            if !visited.contains(&target.section) {
                visited.insert(target.section.clone());
                referenced.push(target.section.clone());
                to_process.push(target.section);
            }
        }
    }

    Ok(referenced)
}

/// Combine a program section with all its subprograms.
/// This follows libbpf's model: when a cross-section call is detected,
/// append ALL functions from the referenced section(s) and fix call targets.
pub fn combine_program_with_subprogs<P: AsRef<Path> + Clone>(
    path: P,
    maps: &[BpfMapDef],
    main_section: &str,
) -> Result<CombinedProgram> {
    use super::prog::{get_functions_in_section, load_bpf_insn_stream_section};
    use crate::parsing::bpf_insn::decode_insns;

    // Load main section instructions
    let main_bytes = load_bpf_insn_stream_section(&path, main_section)?;
    let mut combined_insns = decode_insns(&main_bytes);
    let mut func_offsets: HashMap<String, usize> = HashMap::new();

    // Load main section relocations
    let main_relocs = load_relocations(&path, maps, main_section)?;
    let mut combined_relocs = main_relocs;

    // Collect all sections that are referenced (transitively)
    let referenced_sections = collect_referenced_sections(&path, main_section)?;

    // For each referenced section, load ALL functions
    for ref_section in &referenced_sections {
        // Load the entire section's bytes
        let section_bytes = load_bpf_insn_stream_section(&path, ref_section)?;
        let section_start_pc = combined_insns.len();

        // Get all functions in this section to record their offsets
        let functions = get_functions_in_section(&path, ref_section)?;
        for func in &functions {
            // Compute the PC of this function in the combined program
            let func_pc = section_start_pc + (func.offset / 8);
            func_offsets.insert(func.name.clone(), func_pc);
        }

        // Decode and append all instructions from this section
        let section_insns = decode_insns(&section_bytes);

        // Load relocations for this entire section and adjust PCs
        let section_relocs = load_relocations(&path, maps, ref_section)?;
        for (sec_pc, reloc) in section_relocs {
            let combined_pc = section_start_pc + sec_pc;
            combined_relocs.insert(combined_pc, reloc);
        }

        combined_insns.extend(section_insns);
    }

    // Now fix all BPF call targets
    // For each BpfCall relocation, compute: imm = target_pc - (call_pc + 1)
    for (&call_pc, reloc) in combined_relocs.iter() {
        if reloc.kind == RelocKind::BpfCall
            && let Some(ref target) = reloc.bpf_call_target
            && let Some(&target_pc) = func_offsets.get(&target.func_name)
        {
            // Fix the imm field in the call instruction
            if call_pc < combined_insns.len() {
                let relative_offset = (target_pc as i32) - (call_pc as i32 + 1);
                combined_insns[call_pc].imm = relative_offset;
                combined_insns[call_pc].src = 1; // BPF_PSEUDO_CALL
            }
        }
    }

    fix_pseudo_func_imms(&mut combined_insns, &combined_relocs, &func_offsets);

    // Apply other relocations (maps, helpers)
    apply_relocs(&mut combined_insns, &combined_relocs);

    Ok(CombinedProgram {
        raw_insns: combined_insns,
        pc_to_reloc: combined_relocs,
        func_offsets,
    })
}

/// per-function whole-program loader.
///
/// Like `combine_program_with_subprogs`, but scoped to a single
/// SEC()'d entry function instead of the whole section. Loads
/// `main_func` from `main_section` and transitively appends every
/// `static __noinline` subprog it calls (across sections), then
/// fixes up BpfCall imms so the verifier can follow the chain.
///
/// Why this exists: kernel selftest files often place multiple
/// SEC()'d entries in the same section (`raw_tp`, `kprobe`, ...).
/// `combine_program_with_subprogs` would pull in every entry as
/// "subprograms", which is wrong. This variant loads only the
/// transitive closure of `main_func`'s callees — matching how the
/// kernel test_loader treats one SEC()'d entry as one program.
pub fn combine_function_with_subprogs<P: AsRef<Path> + Clone>(
    path: P,
    maps: &[BpfMapDef],
    main_section: &str,
    main_func: &str,
    extra_roots: &[(String, String)],
) -> Result<CombinedProgram> {
    use super::prog::{get_functions_in_section, load_function_bytes};
    use crate::parsing::bpf_insn::decode_insns;
    use std::collections::HashSet;

    let mut combined_insns: Vec<RawBpfInsn> = Vec::new();
    let mut combined_relocs: HashMap<usize, RelocInfo> = HashMap::new();
    let mut func_offsets: HashMap<String, usize> = HashMap::new();
    let mut visited: HashSet<(String, String)> = HashSet::new();
    // The queue is processed via `pop()` (back of vec). Push extras
    // FIRST so main is popped first → main's body lands at pc 0 (the
    // CFG/analysis entry assumes pc 0 = main entry). Without this,
    // exception_ext_mod_cb_runtime FRs as "unreachable insn at pc 10"
    // because the cb body ends up at pc 0 and the main body at pc 10
    // (CFG DFS from pc 0 walks the cb but never reaches main).
    let mut queue: Vec<(String, String)> = Vec::new();
    for r in extra_roots {
        queue.push(r.clone());
    }
    queue.push((main_section.to_string(), main_func.to_string()));

    while let Some((section, func_name)) = queue.pop() {
        if !visited.insert((section.clone(), func_name.clone())) {
            continue;
        }

        let funcs = get_functions_in_section(&path, &section)?;
        let func = match funcs.iter().find(|f| f.name == func_name) {
            Some(f) => f.clone(),
            None => continue, // extern / not present — fall through to a
                              // BpfCall imm that points nowhere; the
                              // verifier will surface that as a load /
                              // analysis failure.
        };

        let bytes = match load_function_bytes(&path, &section, &func_name) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let insns = decode_insns(&bytes);
        let func_pc_in_combined = combined_insns.len();
        func_offsets.insert(func_name.clone(), func_pc_in_combined);

        // Per-function relocs (PC-rebased to 0 within the function).
        let func_relocs =
            load_relocations_for_function(&path, maps, &section, func.offset, func.size)?;
        for (local_pc, reloc) in func_relocs {
            if matches!(reloc.kind, RelocKind::BpfCall | RelocKind::PseudoFunc)
                && let Some(ref t) = reloc.bpf_call_target
            {
                queue.push((t.section.clone(), t.func_name.clone()));
            }
            combined_relocs.insert(func_pc_in_combined + local_pc, reloc);
        }

        // same-section subprog-to-subprog calls don't
        // carry a relocation — clang fills the call's imm with the real
        // PC-relative offset directly, since the linker doesn't need to
        // touch them. When we splice a subprog body into a different
        // global PC than its original section position, those imms are
        // stale; here we synthesize a `BpfCall` reloc per such insn so
        // the imm-fixup loop below treats them like reloc'd calls.
        for (local_pc, insn) in insns.iter().enumerate() {
            // Skip if this slot already has a reloc.
            if combined_relocs.contains_key(&(func_pc_in_combined + local_pc)) {
                continue;
            }
            if insn.code != 0x85 || insn.src != 1 {
                continue;
            }
            // Resolve the call's target byte offset within `section` and
            // look for the function symbol there.
            let func_byte_off = func.offset as i64;
            let call_byte_off = func_byte_off + (local_pc as i64) * 8;
            let target_byte_off = call_byte_off + 8 + (insn.imm as i64) * 8;
            let mut target_func_name: Option<String> = None;
            for f in &funcs {
                if f.offset as i64 == target_byte_off {
                    target_func_name = Some(f.name.clone());
                    break;
                }
            }
            if let Some(n) = target_func_name {
                queue.push((section.clone(), n.clone()));
                combined_relocs.insert(
                    func_pc_in_combined + local_pc,
                    RelocInfo {
                        map_idx: 0,
                        offset: 0,
                        helper_id: 0,
                        kind: RelocKind::BpfCall,
                        bpf_call_target: Some(BpfCallTarget {
                            func_name: n,
                            section: section.clone(),
                            offset_in_section: target_byte_off as usize,
                            size: 0,
                        }),
                        kfunc_name: None,
                        ..Default::default()
                    },
                );
            }
        }

        combined_insns.extend(insns);
    }

    // Fix BpfCall imms now that all callees have known PCs.
    for (&call_pc, reloc) in combined_relocs.iter() {
        if reloc.kind == RelocKind::BpfCall
            && let Some(ref t) = reloc.bpf_call_target
            && let Some(&target_pc) = func_offsets.get(&t.func_name)
            && call_pc < combined_insns.len()
        {
            let relative_offset = (target_pc as i32) - (call_pc as i32 + 1);
            combined_insns[call_pc].imm = relative_offset;
            combined_insns[call_pc].src = 1; // BPF_PSEUDO_CALL
        }
    }

    // Fix PseudoFunc LD_IMM64 imms similarly. Layout:
    //   src = 4 (BPF_PSEUDO_FUNC)
    //   imm pair = sign-extended (target_pc - ld_pc - 2) in 8-byte units
    fix_pseudo_func_imms(&mut combined_insns, &combined_relocs, &func_offsets);

    apply_relocs(&mut combined_insns, &combined_relocs);

    Ok(CombinedProgram {
        raw_insns: combined_insns,
        pc_to_reloc: combined_relocs,
        func_offsets,
    })
}
