// Attach-target rules: static tables + predicates mirroring kernel-side
// attach validation (struct_ops member allowlists from the test kmods,
// LSM hook availability, tracing attach-target arg tags/kinds, license
// gating). Pure data + string predicates — no verifier state.

use crate::analysis::machine::context::EntryArg;
use crate::parsing::elf::struct_ops::StructOpsBinding;

/// per-(ops_struct, member, arg_idx) PTR_MAYBE_NULL table.
/// See doc comment on `Analyzer::struct_ops_entry_args` for sourcing.
const STRUCT_OPS_MAYBE_NULL_ARGS: &[(&str, &str, u8)] = &[
    ("sched_ext_ops", "dispatch", 1), // prev
    ("sched_ext_ops", "yield", 1),    // to
    // bpf_testmod_ops.test_maybe_null(int dummy, struct task_struct *task):
    // arg 1 (`task`) is registered PTR_MAYBE_NULL by the testmod's
    // bpf_testmod_ops_funcs struct (kernel test_kmods/bpf_testmod.c).
    ("bpf_testmod_ops", "test_maybe_null", 1),
];

pub(crate) fn is_struct_ops_arg_maybe_null(ops_struct: &str, member: &str, arg_idx: u8) -> bool {
    STRUCT_OPS_MAYBE_NULL_ARGS
        .iter()
        .any(|(s, m, i)| *s == ops_struct && *m == member && *i == arg_idx)
}

/// Per-(ops_struct, member, arg_idx) refcounted-arg table. The kernel
/// marks struct_ops member parameters as "ref-acquired at entry" via the
/// `__ref` suffix on the kmod-side parameter name (e.g.
/// `bpf_testmod_ops__test_refcounted(int dummy, struct task_struct *task__ref)`).
/// That suffix lives in the kmod's BTF — not in the BPF program's BTF —
/// so we mirror it here as a static table, the same way
/// STRUCT_OPS_MAYBE_NULL_ARGS mirrors per-arg PTR_MAYBE_NULL.
///
/// The verifier acquires a ref at function entry for each refcounted arg;
/// failure to release it before exit fires UnreleasedReference, matching
/// the kernel's "Unreleased reference id=N alloc_insn=0" rejection on
/// programs like struct_ops_refcounted_fail__ref_leak.
/// Per-(ops_struct, member) `priv_stack_requested` table. The kernel
/// kmod's `check_member` callback sets `prog->aux->priv_stack_requested`
/// for specific members; only those members get PRIV_STACK_ADAPTIVE in
/// `bpf_enable_priv_stack`. Without it, the verifier accumulates depth
/// across the bpf2bpf call chain (`check_max_stack_depth_subprog`).
///
/// Source: vendor/linux/tools/testing/selftests/bpf/test_kmods/bpf_testmod.c
/// `st_ops3_check_member`.
const STRUCT_OPS_PRIV_STACK_REQUESTED: &[(&str, &str)] = &[
    ("bpf_testmod_ops3", "test_1"),
];

pub(crate) fn struct_ops_member_priv_stack_requested(ops_struct: &str, member: &str) -> bool {
    STRUCT_OPS_PRIV_STACK_REQUESTED
        .iter()
        .any(|(s, m)| *s == ops_struct && *m == member)
}

const STRUCT_OPS_REFCOUNTED_ARGS: &[(&str, &str, u8)] = &[
    ("bpf_testmod_ops", "test_refcounted", 1),     // task__ref
    ("bpf_testmod_ops", "test_return_ref_kptr", 1), // task__ref
];

pub(crate) fn is_struct_ops_arg_refcounted(ops_struct: &str, member: &str, arg_idx: u8) -> bool {
    STRUCT_OPS_REFCOUNTED_ARGS
        .iter()
        .any(|(s, m, i)| *s == ops_struct && *m == member && *i == arg_idx)
}

/// Per-(ops_struct, member) table of struct_ops members the kernel module
/// marks unsupported for BPF attach. The kmod's `bpf_struct_ops` registration
/// validates this via `bpf_struct_ops_check_member`/`check_member` callbacks
/// and per-struct allowlists. Without inspecting the kmod we mirror the
/// known-unsupported entries here, matching the kernel's
/// "attach to unsupported member <member> of struct <ops_struct>" rejection.
const UNSUPPORTED_STRUCT_OPS_MEMBERS: &[(&str, &str)] = &[
    ("bpf_testmod_ops", "unsupported_ops"),
    // tcp_congestion_ops: kernel `bpf_tcp_ca_check_member` only permits
    // a fixed allowlist of overridable members (init, release, ssthresh,
    // cong_avoid, set_state, cwnd_event, undo_cwnd, sndbuf_expand,
    // cong_control, name). `get_info` is intentionally not in that set
    // (the kernel reads it via tcp_get_info, not via the ops vtable).
    ("tcp_congestion_ops", "get_info"),
];

pub(crate) fn is_unsupported_struct_ops_member(ops_struct: &str, member: &str) -> bool {
    UNSUPPORTED_STRUCT_OPS_MEMBERS
        .iter()
        .any(|(s, m)| *s == ops_struct && *m == member)
}

/// Per-(ops_struct, member) allowlist of members that may be attached
/// under `SEC("struct_ops.s/<member>")` (sleepable). The kernel module
/// registering each ops struct populates a per-member sleepable mask
/// (see `bpf_struct_ops::cfi_stubs` + `BPF_PROG_TYPE_STRUCT_OPS` attach
/// validation in `bpf_struct_ops_map_link_create`); attempting to attach
/// a non-listed member with the sleepable flavor is rejected with
/// "attach to unsupported member <member> of struct <ops_struct>".
///
/// `bpf_dummy_ops`: only `test_sleepable` is sleepable-allowed (see
/// `dummy_st_ops_fail.c::test_unsupported_field_sleepable` which
/// attaches `.s/test_2` and is `__failure`-asserted).
const STRUCT_OPS_SLEEPABLE_MEMBERS: &[(&str, &str)] = &[
    ("bpf_dummy_ops", "test_sleepable"),
];

pub(crate) fn is_sleepable_allowed_struct_ops_member(ops_struct: &str, member: &str) -> bool {
    STRUCT_OPS_SLEEPABLE_MEMBERS
        .iter()
        .any(|(s, m)| *s == ops_struct && *m == member)
}

/// True iff the SEC string requests the sleepable flavor of struct_ops
/// (`struct_ops.s/<member>` or its libbpf-optional `?struct_ops.s/...`).
pub(crate) fn is_struct_ops_sleepable_sec(section: &str) -> bool {
    let s = section.strip_prefix('?').unwrap_or(section);
    s.starts_with("struct_ops.s/")
}

/// Number of refcounted args declared on this subprog's struct_ops binding.
/// Returns 0 when the subprog has no struct_ops binding or none of its
/// args are refcounted. Consumed by `analyze_program_full` to seed
/// `state.active_refs` at function entry — every refcounted arg becomes
/// an outstanding reference the program must release before exit.
pub(crate) fn struct_ops_refcounted_arg_count(
    bindings: &[StructOpsBinding],
    func_name: &str,
) -> usize {
    let Some(binding) = bindings.iter().find(|b| b.subprog == func_name) else {
        return 0;
    };
    let mut n = 0;
    // The arg_idx in STRUCT_OPS_REFCOUNTED_ARGS is the FUNC_PROTO position
    // (0-based, including any leading scalars). Iterating the table here is
    // O(k) for k=2; same ergonomics as the MAYBE_NULL lookup.
    for (s, m, _) in STRUCT_OPS_REFCOUNTED_ARGS {
        if *s == binding.ops_struct && *m == binding.member {
            n += 1;
        }
    }
    n
}

pub(crate) fn lsm_hook_is_disabled(hook: &str) -> bool {
    matches!(
        hook,
        "vm_enough_memory"
            | "inode_need_killpriv"
            | "inode_getsecurity"
            | "inode_setsecurity"
            | "inode_listsecurity"
            | "inode_copy_up_xattr"
            | "getselfattr"
            | "getprocattr"
            | "setprocattr"
            | "ismaclabel"
            | "secid_to_secctx"
            | "secctx_to_secid"
            | "release_secctx"
            | "d_instantiate"
            | "ipc_getsecid"
            | "key_getsecurity"
            | "audit_rule_match"
            | "audit_rule_init"
            | "audit_rule_free"
            | "module_request"
    )
}

/// Kernel `__noreturn` functions the verifier rejects as fexit/fmod_ret
/// attach targets ("Attaching fexit/fmod_ret to __noreturn functions is
/// rejected."). Mirrors the kernel's `noreturn` attribute set walked by
/// `check_attach_btf_id` — fexit fires on return, so attaching it to a
/// function that never returns is a guaranteed loss-of-control. fentry
/// is allowed; only the post-return tracers are rejected.
/// Kernel functions tracing programs (fentry/fexit/fmod_ret/raw_tp)
/// cannot attach to. The kernel rejects at attach time (not load) via
/// `check_attach_btf_id`'s BPF helper allowlist — these are core
/// locking/CS primitives whose recursion or pre/post observation by
/// BPF would race with the verifier's locking model.
///
/// Test coverage: `tracing_failure.c::test_spin_lock` and
/// `test_spin_unlock` declare `?fentry/bpf_spin_{lock,unlock}` and
/// expect attach failure (note in expectations.json:
/// "kernel prog_tests/tracing_failure.c asserts attach fails").
/// Per-(attach_target, kernel_arg_idx) BTF TYPE_TAG flags carried by the
/// kernel function's arg in vmlinux/module BTF. The kernel verifier's
/// attach-time entry-arg seeder propagates these tags onto the BPF
/// program's R1..Rn (e.g. `__user` → reject direct deref). We don't
/// load module/vmlinux BTF, so mirror just the targets the test corpus
/// exercises.
///
/// `arg_idx` is **kernel-side**: 0 = first user-declared arg of the
/// attach target. Matches `(off / 8)` at the BPF_PROG ctx-array load
/// site, since clang emits one slot per user-declared kernel arg.
const ATTACH_TARGET_ARG_TAGS: &[(&str, u8, crate::analysis::machine::reg_types::PtrFlags)] = &[
    // bpf_testmod_test_btf_type_tag_user_N(struct ... __user *arg)
    ("bpf_testmod_test_btf_type_tag_user_1", 0,
        crate::analysis::machine::reg_types::PtrFlags::USER),
    ("bpf_testmod_test_btf_type_tag_user_2", 0,
        crate::analysis::machine::reg_types::PtrFlags::USER),
    // bpf_testmod_test_btf_type_tag_percpu_N(struct ... __percpu *arg)
    ("bpf_testmod_test_btf_type_tag_percpu_1", 0,
        crate::analysis::machine::reg_types::PtrFlags::PERCPU),
    ("bpf_testmod_test_btf_type_tag_percpu_2", 0,
        crate::analysis::machine::reg_types::PtrFlags::PERCPU),
    // __sys_getsockname(int fd, struct sockaddr __user *usockaddr,
    //                   int __user *usockaddr_len)
    ("__sys_getsockname", 1, crate::analysis::machine::reg_types::PtrFlags::USER),
    ("__sys_getsockname", 2, crate::analysis::machine::reg_types::PtrFlags::USER),
];

pub fn tracing_attach_arg_tag_flags(
    target: Option<&str>,
    arg_idx: u8,
) -> crate::analysis::machine::reg_types::PtrFlags {
    let Some(target) = target else {
        return crate::analysis::machine::reg_types::PtrFlags::empty();
    };
    ATTACH_TARGET_ARG_TAGS
        .iter()
        .filter(|(t, i, _)| *t == target && *i == arg_idx)
        .fold(
            crate::analysis::machine::reg_types::PtrFlags::empty(),
            |acc, (_, _, f)| acc.union(*f),
        )
}

/// Tracing-attach arg kind: scalar vs pointer. `Pointer` is the safe
/// default (matches the lax `TrustedPtr{type_name: "unknown"}`
/// fallback for unmodeled attach targets); `Scalar` is the per-target
/// override used when we know from the kernel function's signature
/// that the slot is an integer/char/short rather than a pointer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TracingArgKind {
    Scalar,
}

/// Per-attach-target arg-kind table. The kernel resolves args from the
/// attach target's vmlinux/module BTF (which knows e.g. that
/// `bpf_fentry_test6`'s arg 3 is `int`, a scalar, not a pointer); we
/// don't ship that BTF, so the lax `is_valid_ctx_read` fallback types
/// every BPF_PROG ctx-array slot as a trusted unknown pointer. That
/// over-types scalar slots and makes downstream comparisons
/// (`c == 18`) look like pointer arithmetic, rejected as "Invalid
/// pointer arithmetic".
///
/// Each entry overrides one slot for one target to `Scalar`. Unmapped
/// slots keep the lax pointer typing.
///
/// `arg_idx` is **kernel-side** (0 = first user-declared arg of the
/// attach target). For fexit programs the trailing `int ret` parameter
/// is appended at slot N (where N = number of kernel args); we don't
/// emit a `Scalar` mapping for it because the BPF_PROG thunk binds the
/// final arg to ctx[N] separately and the existing model already
/// handles it.
const ATTACH_TARGET_ARG_KINDS: &[(&str, u8, TracingArgKind)] = &[
    // bpf_fentry_test1(int a)
    ("bpf_fentry_test1", 0, TracingArgKind::Scalar),
    // bpf_fentry_test2(int a, __u64 b)
    ("bpf_fentry_test2", 0, TracingArgKind::Scalar),
    ("bpf_fentry_test2", 1, TracingArgKind::Scalar),
    // bpf_fentry_test3(char a, int b, __u64 c)
    ("bpf_fentry_test3", 0, TracingArgKind::Scalar),
    ("bpf_fentry_test3", 1, TracingArgKind::Scalar),
    ("bpf_fentry_test3", 2, TracingArgKind::Scalar),
    // bpf_fentry_test4(void *a, char b, int c, __u64 d)
    ("bpf_fentry_test4", 1, TracingArgKind::Scalar),
    ("bpf_fentry_test4", 2, TracingArgKind::Scalar),
    ("bpf_fentry_test4", 3, TracingArgKind::Scalar),
    // bpf_fentry_test5(__u64 a, void *b, short c, int d, __u64 e)
    ("bpf_fentry_test5", 0, TracingArgKind::Scalar),
    ("bpf_fentry_test5", 2, TracingArgKind::Scalar),
    ("bpf_fentry_test5", 3, TracingArgKind::Scalar),
    ("bpf_fentry_test5", 4, TracingArgKind::Scalar),
    // bpf_fentry_test6(__u64 a, void *b, short c, int d, void *e, __u64 f)
    ("bpf_fentry_test6", 0, TracingArgKind::Scalar),
    ("bpf_fentry_test6", 2, TracingArgKind::Scalar),
    ("bpf_fentry_test6", 3, TracingArgKind::Scalar),
    ("bpf_fentry_test6", 5, TracingArgKind::Scalar),
    // bpf_fentry_test7 / 8: single struct ptr arg — already pointer-typed.

    // fexit ret-slot overrides: clang's BPF_PROG-fexit thunk binds the
    // return value to ctx[N] where N is the kernel-side arg count.
    // All bpf_fentry_test* and bpf_testmod_fentry_test* return `int`
    // (a scalar), so the same lax pointer fallback over-types the ret
    // slot. Mark each. These entries only fire for fexit programs;
    // fentry programs never load slot N.
    ("bpf_fentry_test1", 1, TracingArgKind::Scalar),
    ("bpf_fentry_test2", 2, TracingArgKind::Scalar),
    ("bpf_fentry_test3", 3, TracingArgKind::Scalar),
    ("bpf_fentry_test4", 4, TracingArgKind::Scalar),
    ("bpf_fentry_test5", 5, TracingArgKind::Scalar),
    ("bpf_fentry_test6", 6, TracingArgKind::Scalar),
    ("bpf_testmod_fentry_test7", 7, TracingArgKind::Scalar),
    ("bpf_testmod_fentry_test11", 11, TracingArgKind::Scalar),

    // testmod many-args targets:
    // bpf_testmod_fentry_test7(__u64 a, void *b, short c, int d, void *e, char f, int g)
    ("bpf_testmod_fentry_test7", 0, TracingArgKind::Scalar),
    ("bpf_testmod_fentry_test7", 2, TracingArgKind::Scalar),
    ("bpf_testmod_fentry_test7", 3, TracingArgKind::Scalar),
    ("bpf_testmod_fentry_test7", 5, TracingArgKind::Scalar),
    ("bpf_testmod_fentry_test7", 6, TracingArgKind::Scalar),
    // bpf_testmod_fentry_test11(__u64 a, void *b, short c, int d, void *e,
    //                           char f, int g, __u64 h, __u64 i, __u64 j,
    //                           void *k)
    ("bpf_testmod_fentry_test11", 0, TracingArgKind::Scalar),
    ("bpf_testmod_fentry_test11", 2, TracingArgKind::Scalar),
    ("bpf_testmod_fentry_test11", 3, TracingArgKind::Scalar),
    ("bpf_testmod_fentry_test11", 5, TracingArgKind::Scalar),
    ("bpf_testmod_fentry_test11", 6, TracingArgKind::Scalar),
    ("bpf_testmod_fentry_test11", 7, TracingArgKind::Scalar),
    ("bpf_testmod_fentry_test11", 8, TracingArgKind::Scalar),
    ("bpf_testmod_fentry_test11", 9, TracingArgKind::Scalar),

    // fmod_ret/update_socket_protocol(int family, int type, int protocol)
    // — all three int args are scalar. Lax-fallback over-typing makes
    // `R7 << 32` (sign-extending the loaded `type`) look like ptr-arith.
    // Closes mptcpify.c::mptcpify.
    ("update_socket_protocol", 0, TracingArgKind::Scalar),
    ("update_socket_protocol", 1, TracingArgKind::Scalar),
    ("update_socket_protocol", 2, TracingArgKind::Scalar),

    // LSM hook attach targets — trailing scalar args. The `entry_args`
    // table in `derive_program_kind`'s LSM dispatch only declares the
    // BTF-typed pointer prefix; trailing slots fall through to the lax
    // `TrustedPtr{type_name: "unknown"}` fallback and over-type as
    // pointers. These overrides flip the int/gfp_t/addrlen slots back
    // to Scalar for hooks the lsm_cgroup corpus exercises.
    //
    // socket_post_create(struct socket *sock, int family, int type,
    //                    int protocol, int kern)
    ("socket_post_create", 1, TracingArgKind::Scalar),
    ("socket_post_create", 2, TracingArgKind::Scalar),
    ("socket_post_create", 3, TracingArgKind::Scalar),
    ("socket_post_create", 4, TracingArgKind::Scalar),
    // socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
    ("socket_bind", 2, TracingArgKind::Scalar),
    // sk_alloc_security(struct sock *sk, int family, gfp_t priority)
    ("sk_alloc_security", 1, TracingArgKind::Scalar),
    ("sk_alloc_security", 2, TracingArgKind::Scalar),
    // file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
    //               unsigned long prot, int ret)
    ("file_mprotect", 1, TracingArgKind::Scalar),
    ("file_mprotect", 2, TracingArgKind::Scalar),
    ("file_mprotect", 3, TracingArgKind::Scalar),
    // inet_csk_clone(struct sock *newsk, const struct request_sock *req)
    // — both pointers, no scalar slots.
];

/// Look up the per-target arg kind. Returns `None` for unmapped slots
/// (callers should keep the lax pointer fallback).
pub fn tracing_attach_arg_kind(target: Option<&str>, arg_idx: u8) -> Option<TracingArgKind> {
    let target = target?;
    ATTACH_TARGET_ARG_KINDS
        .iter()
        .find(|(t, i, _)| *t == target && *i == arg_idx)
        .map(|(_, _, k)| *k)
}

/// LSM int-hook trailing scalar args appended after the typed-pointer
/// prefix. Kernel constrains `int ret` to `[-MAX_ERRNO, 0]` at attach
/// (so `return ret;` patterns satisfy the LSM retval rule). Trailing
/// positional `unsigned long` args (e.g. `reqprot`, `prot` for
/// `file_mprotect`) are bounded ≥ 0 in principle, but no current test
/// depends on those bounds — we emit plain `Scalar` slots to keep
/// kernel arg layout aligned and only bound the final `ret` slot.
pub(crate) fn lsm_int_hook_trailing_args(
    prog_kind: crate::ast::ProgramKind,
    target: &str,
) -> Vec<EntryArg> {
    use crate::ast::ProgramKind;
    use crate::common::constants::MAX_ERRNO;
    if prog_kind != ProgramKind::Lsm {
        return Vec::new();
    }
    match target {
        // file_mprotect(struct vm_area_struct *vma,
        //               unsigned long reqprot,
        //               unsigned long prot, int ret)
        "file_mprotect" => vec![
            EntryArg::Scalar,
            EntryArg::Scalar,
            EntryArg::BoundedScalar { lo: -MAX_ERRNO, hi: 0 },
        ],
        _ => Vec::new(),
    }
}

/// Number of typed-pointer args at the head of an LSM int-hook's
/// arg list. Used to splice the pointer prefix from BTF resolution
/// with the static `lsm_int_hook_trailing_args` tail.
pub(crate) fn lsm_int_hook_pointer_prefix(target: &str) -> usize {
    match target {
        "file_mprotect" => 1, // (vma)
        _ => 0,
    }
}

pub(crate) fn is_tracing_attach_denied(target: &str) -> bool {
    matches!(
        target,
        // Locked-helper family: see tracing_failure.c.
        "bpf_spin_lock" | "bpf_spin_unlock"
        // sk_storage subsystem: tracing self-recursion. Kernel
        // `bpf_sk_storage_tracing_allowed` rejects fentry attach to
        // bpf_sk_storage_free (the helper would re-enter the storage
        // subsystem). See test_sk_storage_trace_itself.c.
        | "bpf_sk_storage_free"
    )
}

pub(crate) fn is_noreturn_kernel_fn(name: &str) -> bool {
    matches!(
        name,
        "__module_put_and_kthread_exit"
            | "__kthread_exit"
            | "__x64_sys_exit"
            | "__x64_sys_exit_group"
            | "__ia32_sys_exit"
            | "__ia32_sys_exit_group"
            | "do_exit"
            | "do_group_exit"
            | "do_task_dead"
            | "kthread_complete_and_exit"
            | "kthread_exit"
            | "make_task_dead"
            | "rewind_stack_and_make_dead"
    )
}


pub(crate) fn license_is_gpl_compatible(s: &str) -> bool {
    matches!(
        s,
        "GPL" | "GPL v2" | "GPL and additional rights" | "Dual BSD/GPL"
            | "Dual MIT/GPL" | "Dual MPL/GPL"
    )
}

/// struct_ops types the kernel registers as `BPF_PROG_GPL_ONLY`. Loading
/// a non-GPL-compatible BPF program against any of these is rejected by
/// the struct_ops registration path at attach time.
pub(crate) const GPL_ONLY_STRUCT_OPS: &[&str] = &[
    "tcp_congestion_ops",
];

