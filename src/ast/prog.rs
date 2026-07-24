// src/ast/prog.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProgramKind {
    Unspec,
    SocketFilter,
    Kprobe,
    SchedCls,
    SchedAct,
    Tracepoint,
    Xdp,
    PerfEvent,
    CgroupSkb,
    CgroupSock,
    LwtIn,
    LwtOut,
    LwtXmit,
    SockOps,
    SkSkb,
    SkLookup,
    CgroupDevice,
    SkMsg,
    RawTracepoint,
    RawTracepointWritable,
    CgroupSockAddr,
    /// `SEC("cgroup/getsockopt")` and `SEC("cgroup/setsockopt")` —
    /// BPF_PROG_TYPE_CGROUP_SOCKOPT. Receives `struct bpf_sockopt *` ctx;
    /// distinguishes attach type via the SEC suffix so retval-write rules
    /// can be enforced (kernel allows write only for setsockopt).
    CgroupSockopt,
    Lsm,
    Tracing,
    /// `SEC("syscall")` — BPF_PROG_TYPE_SYSCALL (kernel v5.11+).
    /// Distinct from generic Unknown so the prog-type allowlist
    /// can permit cgroup / cpumask / task kfuncs in syscall programs
    /// (where they're allowed) but reject in raw_tp.
    Syscall,
    /// `SEC("struct_ops[.s]/<member>")` or bare `SEC("struct_ops")`
    /// — BPF_PROG_TYPE_STRUCT_OPS (kernel v5.6+, expanded by sched_ext
    /// in v6.12). Each program implements one member of an ops-struct
    /// (`tcp_congestion_ops.init`, `sched_ext_ops.dispatch`, …); R1..Rn
    /// entry types are derived from that member's BTF FUNC_PROTO by the
    ///  entry-state plumbing.
    StructOps,
    /// `SEC("netfilter")` — BPF_PROG_TYPE_NETFILTER. R0 at exit must be a
    /// known value in [0, 1] (NF_DROP / NF_ACCEPT).
    Netfilter,
    /// `SEC("flow_dissector")` — BPF_PROG_TYPE_FLOW_DISSECTOR. Receives
    /// `struct __sk_buff *` ctx but with a stricter allowlist than the
    /// generic SkBuff context (only `data`, `data_end`, `flow_keys`).
    FlowDissector,
    /// `SEC("sk_reuseport")` — BPF_PROG_TYPE_SK_REUSEPORT. Receives
    /// `struct sk_reuseport_md *` ctx directly (no BPF_PROG wrapper);
    /// ctx-access is BTF-driven via `field_at_offset` on the iter-style
    /// path in `validate_ctx_access`.
    SkReuseport,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ContextKind {
    XdpMd,
    SkBuff,
    SkLookup,
    SkReuseport,
    SockOps,
    BpfSock,
    SkMsgMd,
    BpfSockAddr,
    BpfSockopt,
    PtRegs,
    IterTask,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachKind {
    TraceRawTp,
    TraceIter,
    Unknown,
}

impl ProgramKind {
    pub fn from_section(s: &str) -> Self {
        let s = s.to_lowercase();
        let s = s.trim();

        // ---- Modern aliases ----
        //
        // Recognized natively rather than relying on incidental
        // `starts_with("tc")` matches or falling through to Unknown. Each
        // modern SEC routes to its underlying kernel prog_type (libbpf's
        // section_defs[] is the source of truth):
        //   `tcx/{ingress,egress}` / `netkit/{primary,peer}` → sched_cls
        //   `fentry[.s]/`, `fexit[.s]/`, `fmod_ret[.s]/`, `tp_btf/`,
        //     `iter[.s]/` → tracing
        //   `raw_tp[.w][/…]` → raw_tracepoint
        //   `lsm[.s]/` → lsm
        //   `uprobe[.s]/`, `uretprobe[.s]/` → kprobe
        //   `cgroup_skb/{ingress,egress}` (libbpf modern form, distinct
        //     from legacy `cgroup/skb`) → cgroup_skb
        //
        // SECs without a corresponding ProgramKind variant
        // (`syscall`, `flow_dissector`, `sk_reuseport`, `sk_lookup`,
        // `struct_ops/*`, `netfilter/*`) intentionally fall through to
        // Unknown — adding variants is / territory.
        if s.starts_with("tcx/") || s.starts_with("netkit/") {
            return ProgramKind::SchedCls;
        }
        // Normalize libbpf's optional-load `?` prefix for tracing-class
        // SECs (fentry/fexit/fmod_ret/iter/lsm/raw_tp/uprobe/kprobe/
        // tracepoint/perf_event/syscall/freplace). The `?` is purely
        // libbpf-internal optionality — kernel reaches the same prog_type
        // and applies the same kfunc/helper allowlists either way. The
        // strip is TARGETED to tracing-class prefixes (not blanket) so
        // unrelated SECs (struct_ops, xdp, cgroup_skb) keep their
        // bespoke handling.
        let tr_view: &str = match s.strip_prefix('?') {
            Some(rest)
                if rest.starts_with("fentry/")
                    || rest.starts_with("fentry.s/")
                    || rest.starts_with("fexit/")
                    || rest.starts_with("fexit.s/")
                    || rest.starts_with("fmod_ret/")
                    || rest.starts_with("fmod_ret.s/")
                    || rest.starts_with("iter/")
                    || rest.starts_with("iter.s/")
                    || rest.starts_with("lsm/")
                    || rest.starts_with("lsm.s/")
                    || rest.starts_with("lsm_cgroup/")
                    || rest.starts_with("lsm_cgroup.s/")
                    || rest.starts_with("raw_tp/")
                    || rest.starts_with("raw_tp.w/")
                    || rest == "raw_tp"
                    || rest == "raw_tp.w"
                    || rest.starts_with("uprobe/")
                    || rest.starts_with("uprobe.s/")
                    || rest.starts_with("uretprobe/")
                    || rest.starts_with("uretprobe.s/")
                    || rest.starts_with("kprobe/")
                    || rest.starts_with("kretprobe/")
                    || rest.starts_with("tracepoint/")
                    || rest == "tracepoint"
                    || rest.starts_with("perf_event")
                    || rest == "syscall"
                    || rest.starts_with("freplace/")
                    // libbpf-managed optional SECs: `?tc`, `?xdp`,
                    // `?cgroup_*`, etc. produce the same prog_type as
                    // their non-`?` counterparts; the `?` is purely
                    // libbpf-internal optionality (skel-load doesn't
                    // require these to verify). Without stripping,
                    // they fall through to ProgramKind::Unknown and
                    // their ctx loads/helpers don't get the right
                    // model.
                    || rest == "tc"
                    || rest.starts_with("tc/")
                    || rest == "xdp"
                    || rest.starts_with("xdp/")
                    || rest.starts_with("cgroup_skb/")
                    || rest.starts_with("cgroup/") =>
            {
                rest
            }
            _ => s,
        };
        if tr_view.starts_with("fentry/")
            || tr_view.starts_with("fentry.s/")
            || tr_view.starts_with("fexit/")
            || tr_view.starts_with("fexit.s/")
            || tr_view.starts_with("fmod_ret/")
            || tr_view.starts_with("fmod_ret.s/")
            || tr_view.starts_with("tp_btf/")
            || s.starts_with("?tp_btf/")
            || tr_view.starts_with("iter/")
            || tr_view.starts_with("iter.s/")
        {
            return ProgramKind::Tracing;
        }
        if tr_view == "raw_tp"
            || tr_view.starts_with("raw_tp/")
            || tr_view.starts_with("raw_tp.w/")
            || tr_view == "raw_tp.w"
        {
            return ProgramKind::RawTracepoint;
        }
        if tr_view.starts_with("lsm/")
            || tr_view.starts_with("lsm.s/")
            || tr_view.starts_with("lsm_cgroup/")
            || tr_view.starts_with("lsm_cgroup.s/")
        {
            return ProgramKind::Lsm;
        }
        if tr_view.starts_with("uprobe/")
            || tr_view.starts_with("uprobe.s/")
            || tr_view.starts_with("uretprobe/")
            || tr_view.starts_with("uretprobe.s/")
            || tr_view == "uprobe.session"
            || tr_view == "uretprobe.session"
            || tr_view == "kprobe.session"
            || tr_view == "kretprobe.session"
        {
            return ProgramKind::Kprobe;
        }
        if tr_view == "syscall" {
            return ProgramKind::Syscall;
        }
        if s == "netfilter" || s.starts_with("netfilter/") {
            return ProgramKind::Netfilter;
        }
        if s == "flow_dissector" || s.starts_with("flow_dissector/") {
            return ProgramKind::FlowDissector;
        }
        if s == "sk_reuseport" || s.starts_with("sk_reuseport/") {
            return ProgramKind::SkReuseport;
        }
        // struct_ops. Forms in the wild:
        //   "struct_ops"             — bare, member named after func symbol
        //   "struct_ops/<member>"    — explicit member binding
        //   "struct_ops.s/<member>"  — sleepable variant
        //   "?struct_ops/<member>"   — optional (libbpf "weak") binding
        // The leading "?" is libbpf-internal optionality; strip before match.
        let trimmed = s.strip_prefix('?').unwrap_or(s);
        if trimmed == "struct_ops"
            || trimmed.starts_with("struct_ops/")
            || trimmed.starts_with("struct_ops.s/")
        {
            return ProgramKind::StructOps;
        }

        // ---- Common tc section aliases used by Cilium/Suricata-style objects ----
        if matches!(
            s,
            "from-netdev"
                | "to-netdev"
                | "from-container"
                | "to-container"
                | "filter"
                | "bypass_filter"
                | "loadbalancer"
                | "lb"
                | "vlan_filter"
        ) {
            return ProgramKind::SchedCls;
        }
        // Accept libbpf optional-load form `?xdp[.frags][/<func>]` too —
        // needed for `verifier_global_subprogs.c::arg_tag_dynptr` (and
        // the dynptr_fail.c::xdp_* family) so the prog-type allowlist
        // on `bpf_dynptr_from_xdp` recognizes the caller as XDP. Other
        // optional tracing flavors are intentionally NOT stripped
        // (`?fentry/`, `?fexit/`) — corpus tests rely on the resulting
        // Unknown kfunc-rejection. See `?tp_btf/` arm above for the
        // analogous targeted exception.
        if s.starts_with("xdp") || s.starts_with("?xdp") {
            return ProgramKind::Xdp;
        }
        // Hotfix for OVS datapath benchmark: datapath.o utilizes bpf_tail_call
        // from ingress/egress (SchedCls) into sections prefixed with "tail-" and "downcall".
        // Since caller and callee must have the same program type, these target
        // sections execute under the SchedCls context (SkBuff). This is a fast-path
        // assumption and not a general mechanism for sound program kind inference.
        if tr_view.starts_with("classifier")
            || tr_view.starts_with("tc")
            || tr_view.starts_with("sched_cls")
            || tr_view.starts_with("action")
            || tr_view.starts_with("ingress")
            || tr_view.starts_with("egress")
            || tr_view.starts_with("l2_")
            || tr_view.starts_with("drop_")
            || tr_view.starts_with("tail")
            || s.starts_with("downcall")
        {
            return ProgramKind::SchedCls;
        }
        if s.starts_with("socket") {
            return ProgramKind::SocketFilter;
        }
        if s.starts_with("sockops") {
            return ProgramKind::SockOps;
        }
        if s.starts_with("sk_msg") {
            return ProgramKind::SkMsg;
        }
        // SK_SKB / sockmap programs: stream parser/verdict callbacks on
        // a sockmap-attached socket. Section names include `sk_skb`,
        // `sk_skb1`, `sk_skb2`, `sk_skb/stream_parser`,
        // `sk_skb/stream_verdict`. Ctx is __sk_buff, so the SK_BUFF_FIELDS
        // table (with `data` @ 76 → PacketStart, `data_end` @ 80 →
        // PacketEnd) types loads correctly. Without this mapping the
        // program kind falls through to Unknown and ctx field loads
        // return Scalar.
        if s.starts_with("sk_skb") {
            return ProgramKind::SkSkb;
        }
        // Recognize libbpf optional-load `?cgroup[_skb]/...` form alongside
        // bare `cgroup[_skb]/...` for the sock_addr / sockopt / sock-create
        // and skb hook families. Files using these include dynptr_success
        // (`?cgroup_skb/egress`), test_ldsx_insn (`?cgroup/getsockopt`),
        // and test_ns_current_pid_tgid (`?cgroup/bind4`). We intentionally
        // do NOT strip `?` globally — see
        // `feedback_fix_unmasks_kernel_rejection` (a global strip in past
        // sessions unmasked kfunc-allowlist rejections in dynptr_fail
        // siblings, producing 4 FAs).
        let cg_view: &str = match s.strip_prefix('?') {
            Some(rest) if rest.starts_with("cgroup/") || rest.starts_with("cgroup_skb/") => rest,
            _ => s,
        };
        if cg_view.starts_with("cgroup/bind")
            || cg_view.starts_with("cgroup/connect")
            || cg_view.starts_with("cgroup/sendmsg")
            || cg_view.starts_with("cgroup/recvmsg")
            || cg_view.starts_with("cgroup/getpeername")
            || cg_view.starts_with("cgroup/getsockname")
        {
            return ProgramKind::CgroupSockAddr;
        }
        if cg_view.starts_with("cgroup_skb/") {
            return ProgramKind::CgroupSkb;
        }
        if cg_view.starts_with("cgroup/skb") {
            return ProgramKind::CgroupSkb;
        }
        // cgroup/getsockopt and cgroup/setsockopt must be matched before the
        // generic "cgroup/sock*" arm below, otherwise they collapse into
        // CgroupSock and pick up the wrong (bpf_sock) context layout.
        if cg_view.starts_with("cgroup/getsockopt") || cg_view.starts_with("cgroup/setsockopt") {
            return ProgramKind::CgroupSockopt;
        }
        if cg_view.starts_with("cgroup/sock") || cg_view.starts_with("cgroup/post_bind") {
            return ProgramKind::CgroupSock;
        }
        if tr_view.starts_with("kprobe") || tr_view.starts_with("kretprobe") {
            return ProgramKind::Kprobe;
        }
        if tr_view.starts_with("tracepoint") {
            return ProgramKind::Tracepoint;
        }
        if tr_view.starts_with("raw_tracepoint") {
            return ProgramKind::RawTracepoint;
        }
        if tr_view.starts_with("perf_event") {
            return ProgramKind::PerfEvent;
        }
        if s == "sk_lookup" || s.starts_with("sk_lookup/") {
            return ProgramKind::SkLookup;
        }
        // LWT attach types share __sk_buff context. `lwt_in`/`lwt_out`/
        // `lwt_xmit` map to the corresponding ProgramKind; `lwt_seg6local`
        // also uses __sk_buff so route it to LwtXmit (closest ctx-access
        // semantics — kernel verifies the same set of skb fields plus
        // the seg6local-specific helper allowlist, which is orthogonal).
        if s == "lwt_in" {
            return ProgramKind::LwtIn;
        }
        if s == "lwt_out" {
            return ProgramKind::LwtOut;
        }
        if s == "lwt_xmit" || s == "lwt_seg6local" {
            return ProgramKind::LwtXmit;
        }
        // Custom SEC names used by test_lwt_redirect.c — the userspace
        // driver (prog_tests/lwt_redirect.c) calls
        // bpf_program__set_type(BPF_PROG_TYPE_LWT_{IN,OUT}) keyed on these
        // SEC names. The `_nomac` suffix only changes attach configuration
        // on the user side; both share the same kernel prog_type and
        // therefore the same __sk_buff ctx layout.
        if s == "redir_ingress" || s == "redir_ingress_nomac" {
            return ProgramKind::LwtIn;
        }
        if s == "redir_egress" || s == "redir_egress_nomac" {
            return ProgramKind::LwtOut;
        }
        // Custom SEC names used by test_lwt_seg6local.c. The userspace
        // driver loads these via `ip route ... encap bpf in obj <obj>
        // sec encap_srh ...` (LwtIn-style encap insertion) or
        // `... encap seg6local action End.BPF endpoint obj <obj>
        // sec <add_egr_x|pop_egr|inspect_t> ...` (LwtSeg6local action
        // BPF endpoints). Both classes share the __sk_buff ctx layout;
        // routing the seg6local actions to LwtXmit (which we already
        // route lwt_seg6local to above) gives them the correct
        // skb->data / skb->data_end packet typing.
        if s == "encap_srh" {
            return ProgramKind::LwtIn;
        }
        if s == "add_egr_x" || s == "pop_egr" || s == "inspect_t" {
            return ProgramKind::LwtXmit;
        }
        ProgramKind::Unknown
    }

    pub fn context_kind(&self) -> ContextKind {
        match self {
            ProgramKind::Xdp => ContextKind::XdpMd,
            ProgramKind::SchedCls
            | ProgramKind::SocketFilter
            | ProgramKind::SchedAct
            | ProgramKind::SkSkb
            | ProgramKind::CgroupSkb
            | ProgramKind::LwtIn
            | ProgramKind::LwtOut
            | ProgramKind::LwtXmit
            | ProgramKind::Lsm
            | ProgramKind::RawTracepoint
            | ProgramKind::FlowDissector => ContextKind::SkBuff,
            ProgramKind::SockOps => ContextKind::SockOps,
            ProgramKind::SkLookup => ContextKind::SkLookup,
            ProgramKind::SkReuseport => ContextKind::SkReuseport,
            ProgramKind::SkMsg => ContextKind::SkMsgMd,
            ProgramKind::CgroupSockAddr => ContextKind::BpfSockAddr,
            ProgramKind::CgroupSockopt => ContextKind::BpfSockopt,
            ProgramKind::CgroupSock => ContextKind::BpfSock,
            _ => ContextKind::Unknown,
        }
    }

    pub fn requires_strict_return_code(&self) -> bool {
        matches!(
            self,
            ProgramKind::CgroupSkb | ProgramKind::CgroupSock | ProgramKind::CgroupSockAddr
        )
    }
}

/// Per-attach-type return-value rule.
///
/// Mirrors the kernel's `check_return_code` per-prog-type / per-expected-attach-type
/// table: at program exit, R0 must lie in `[lo, hi]`, and if `require_known` is
/// true, R0 must additionally be a single known value (smin == smax).
///
/// `subtype` is the SEC suffix after the first `/` lowercased — e.g. for
/// `SEC("cgroup/recvmsg4")` it is `"recvmsg4"`; for `SEC("lsm/file_mprotect")`
/// it is `"file_mprotect"`. For prog kinds whose retval rule does not depend
/// on attach subtype (e.g. netfilter), `subtype` is unused.
#[derive(Debug, Clone, Copy)]
pub struct RetvalRule {
    pub lo: i64,
    pub hi: i64,
    pub require_known: bool,
}

pub fn expected_retval_rule(prog_kind: ProgramKind, subtype: Option<&str>) -> Option<RetvalRule> {
    match prog_kind {
        ProgramKind::CgroupSockAddr => {
            let sub = subtype?;
            // recvmsg / getpeername / getsockname: must return exactly 1.
            if sub.starts_with("recvmsg")
                || sub.starts_with("getpeername")
                || sub.starts_with("getsockname")
            {
                return Some(RetvalRule { lo: 1, hi: 1, require_known: false });
            }
            // bind4 / bind6: [0, 3].
            if sub.starts_with("bind") {
                return Some(RetvalRule { lo: 0, hi: 3, require_known: false });
            }
            // sendmsg / connect: [0, 1] (default for cgroup/sock_addr hooks).
            Some(RetvalRule { lo: 0, hi: 1, require_known: false })
        }
        ProgramKind::Lsm => {
            let sub = subtype?;
            // bool retval hooks.
            if sub == "audit_rule_known" {
                return Some(RetvalRule { lo: 0, hi: 1, require_known: false });
            }
            // void retval hooks: no constraint.
            if sub == "file_free_security" || sub == "task_free" || sub == "inode_free_security" {
                return None;
            }
            // Default LSM hook: errno-or-zero. Only enforce on hooks we know
            // are checked upstream (avoid regressing PASS cases that we
            // currently accept but where the kernel's per-hook policy is
            // looser than [-4095, 0]).
            if sub == "file_mprotect" {
                return Some(RetvalRule { lo: -4095, hi: 0, require_known: false });
            }
            None
        }
        ProgramKind::Netfilter => {
            // NF_DROP=0, NF_ACCEPT=1; kernel additionally requires the value
            // to be a known constant (rejects "R0 is not a known value").
            Some(RetvalRule { lo: 0, hi: 1, require_known: true })
        }
        ProgramKind::Kprobe => {
            // SEC("kprobe.session") and SEC("uprobe.session"): the
            // kernel's session-attach hook expects R0 ∈ [0, 1] at exit
            // — 0 means "skip the matching kretprobe", 1 means "run
            // it". Plain `kprobe`/`uprobe` programs don't constrain R0.
            // Both share ProgramKind::Kprobe; the subtype derived from
            // the SEC string disambiguates.
            if matches!(subtype, Some("session")) {
                return Some(RetvalRule { lo: 0, hi: 1, require_known: false });
            }
            None
        }
        _ => None,
    }
}
