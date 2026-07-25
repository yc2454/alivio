//! Plain-data BTF type definitions and module-wide constants.
//!
//! Holds:
//!   * BTF_KIND_* constants (BTF spec wire encoding).
//!   * The parsed-type structs (`BtfType`, `BtfMember`, `DeclTag`).
//!   * The verifier-facing field/special-field enums.
//!   * The `BtfContext` struct definition (impls live in `context/`).
//!   * `DatasecEntry`, `StructOpsArg`, `GlobalFuncArg`.
//!   * Free helpers `is_ctx_struct_name` / `refine_global_arg_with_tags`.

use std::collections::{HashMap, HashSet};

/// Decoded view of the 24-byte BTF section header. Both `parse_btf` and
/// `parse_btf_map_defs` start by reading the same fields; this struct
/// shares the decode and the bounds check.
pub(super) struct BtfHeader {
    /// Absolute byte offset where the type entries begin.
    pub type_start: usize,
    /// One-past-the-last byte of the type-entries region.
    pub type_end: usize,
    /// Absolute byte offset where the strings blob begins.
    pub str_start: usize,
    /// One-past-the-last byte of the strings blob.
    pub str_end: usize,
}

impl BtfHeader {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, String> {
        use std::convert::TryInto;
        if bytes.len() < 24 {
            return Err("BTF too short".into());
        }
        let hdr_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let type_off = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let type_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let str_off = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let str_len = u32::from_le_bytes(bytes[20..24].try_into().unwrap());

        let type_start = (hdr_len + type_off) as usize;
        let type_end = type_start + type_len as usize;
        let str_start = (hdr_len + str_off) as usize;
        let str_end = str_start + str_len as usize;

        if type_end > bytes.len() || str_end > bytes.len() {
            return Err("BTF sections out of bounds".into());
        }
        Ok(BtfHeader {
            type_start,
            type_end,
            str_start,
            str_end,
        })
    }
}

// Kinds
pub const BTF_KIND_INT: u8 = 1;
pub const BTF_KIND_PTR: u8 = 2;
pub const BTF_KIND_ARRAY: u8 = 3;
pub const BTF_KIND_STRUCT: u8 = 4;
pub const BTF_KIND_UNION: u8 = 5;
pub const BTF_KIND_ENUM: u8 = 6;
pub const BTF_KIND_FWD: u8 = 7;
pub const BTF_KIND_TYPEDEF: u8 = 8;
pub const BTF_KIND_VOLATILE: u8 = 9;
pub const BTF_KIND_CONST: u8 = 10;
pub const BTF_KIND_RESTRICT: u8 = 11;
pub const BTF_KIND_FUNC: u8 = 12;
pub const BTF_KIND_FUNC_PROTO: u8 = 13;
pub const BTF_KIND_VAR: u8 = 14;
pub const BTF_KIND_DATASEC: u8 = 15;
pub const BTF_KIND_FLOAT: u8 = 16;
pub const BTF_KIND_DECL_TAG: u8 = 17;
pub const BTF_KIND_TYPE_TAG: u8 = 18;
pub const BTF_KIND_ENUM64: u8 = 19;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialFieldKind {
    SpinLock,
    Timer,
    ListHead,
    ListNode,
    RbRoot,
    RbNode,
    Refcount,
    /// `struct bpf_res_spin_lock` — resilient queued spin lock added in
    /// kernel v6.15. Distinct from `SpinLock` so callers of
    /// `bpf_res_spin_lock` cannot match a plain `bpf_spin_lock` field
    /// (kernel verifier.c L8305 emits "map '<m>' has no valid
    /// bpf_res_spin_lock" when the requested record-flavor is missing).
    ResSpinLock,
    /// `struct bpf_wq` — async work queue, kernel v6.10. The
    /// `bpf_wq_init` / `bpf_wq_set_callback_impl` / `bpf_wq_start`
    /// kfunc family takes a pointer to a wq field embedded in a
    /// map value. Mirrors the Timer family.
    Wq,
    // Future types...
}

impl SpecialFieldKind {
    pub(super) fn from_type_name(name: &str) -> Option<Self> {
        match name {
            "bpf_spin_lock" => Some(Self::SpinLock),
            "bpf_res_spin_lock" => Some(Self::ResSpinLock),
            "bpf_timer" => Some(Self::Timer),
            "bpf_list_head" => Some(Self::ListHead),
            "bpf_list_node" => Some(Self::ListNode),
            "bpf_rb_root" => Some(Self::RbRoot),
            "bpf_rb_node" => Some(Self::RbNode),
            "bpf_refcount" => Some(Self::Refcount),
            "bpf_wq" => Some(Self::Wq),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpecialField {
    pub kind: SpecialFieldKind,
    pub offset: u32, // byte offset
    pub size: u32,
    /// `__contains(struct, member)` decoration on a `bpf_list_head` /
    /// `bpf_rb_root` field. Decoded from a BTF DECL_TAG named
    /// `"contains:<struct>:<member>"` attached to the head field. The
    /// kernel uses this to validate the second arg of
    /// `bpf_list_push_{front,back}` / `bpf_rbtree_add`: the node pointer
    /// must be at the declared `node_offset` inside the declared
    /// container struct. Closes a subset of `linked_list_fail.c` /
    /// `rbtree_btf_fail__add_wrong_type.c` by offset comparison alone
    /// (full pointee-struct match needs PtrToOwnedKptr to carry a
    /// `pointee_btf_id`, which is a separate representation change).
    pub contains: Option<ContainsInfo>,
}

#[derive(Debug, Clone)]
pub struct ContainsInfo {
    /// Name of the contained struct (the `<struct>` in `__contains(struct, member)`).
    /// Always available — taken straight from the decl_tag string.
    pub struct_name: String,
    /// Byte offset of the `bpf_list_node` / `bpf_rb_node` member named
    /// in the decl_tag, within `struct_name`. `None` when the named
    /// struct isn't in the prog's BTF (clang drops types that are only
    /// referenced via decl_tag strings, e.g. `rbtree_btf_fail__add_wrong_type.c`
    /// where `node_data` is named only in `__contains(node_data, node)`).
    /// Validators must skip the offset check when this is None and rely
    /// on the struct-name comparison alone.
    pub node_offset: Option<u32>,
}

/// Result of looking up a struct/union member at a byte offset, for
/// the verifier's load-typing path. See `BtfContext::field_at_offset`.
#[derive(Debug, Clone)]
pub struct BtfFieldInfo<'a> {
    /// Member name (e.g. `"cpus_ptr"`, `"sk"`, `"f_path"`). Borrowed
    /// from the BTF strings table; cheap to clone-into-static via the
    /// `intern_btf_type_name_strict` cache when needed.
    pub name: &'a str,
    pub kind: BtfFieldKind,
}

/// What a struct/union member resolves to after walking through any
/// modifier (TYPEDEF/CONST/VOLATILE/RESTRICT) and TYPE_TAG entries.
#[derive(Debug, Clone)]
pub enum BtfFieldKind {
    /// Pointer field: `pointee_name` is the named struct it points to
    /// (or None if the pointee isn't a named struct — function ptr,
    /// pointer-to-primitive, …). `type_tag` is the kernel TYPE_TAG
    /// annotation seen between the field and the PTR layer
    /// (`"percpu"` / `"user"` / `"rcu"`), or None for plain pointers.
    /// The verifier propagates this onto the loaded reg's PtrFlags so
    /// access-time deref rejection (memory/access.rs) and trust-band
    /// kfunc gating fire correctly.
    Pointer {
        pointee_name: Option<String>,
        type_tag: Option<String>,
    },
    /// Embedded struct/union member (no PTR layer). `type_name` is the
    /// BTF struct name. Used for `&base->field` interior-pointer
    /// arithmetic to produce a typed pointer to the member.
    Embedded { type_name: Option<String> },
    /// Primitive (int, enum, float).
    Scalar,
    /// Anything else — array, function-proto, void, … — caller decides.
    Other,
}

#[derive(Debug, Clone)]
pub struct BtfMember {
    pub name_off: u32,
    pub type_id: u32,
    pub offset: u32, // Offset in bits
}

#[derive(Debug, Clone)]
pub struct BtfType {
    pub id: u32,
    pub name_off: u32,
    pub info: u32,
    pub size_or_type: u32,
    pub members: Vec<BtfMember>,
}

impl BtfType {
    pub fn kind(&self) -> u8 {
        ((self.info >> 24) & 0x1f) as u8
    }
}

/// A BTF_KIND_DECL_TAG: an annotation attached to a type (or a specific struct
/// member / function argument). Used by the kernel to register kfuncs, mark
/// map-value fields as `__kptr`/`__rcu`/`__uptr`, and carry CO-RE hints.
#[derive(Debug, Clone)]
pub struct DeclTag {
    pub name: String,
    pub target_type_id: u32,
    /// -1 for whole-type tags; otherwise the 0-based member/argument index.
    pub component_idx: i32,
}

#[derive(Clone, Default, Debug)]
pub struct BtfContext {
    pub types: HashMap<u32, BtfType>,
    pub strings: Vec<u8>,
    /// All DECL_TAGs parsed from the BTF section. Populated by `parse_btf`.
    pub(super) decl_tags: Vec<DeclTag>,
    /// Index of kfunc FUNC types by name: name -> FUNC btf_id. A FUNC is
    /// considered a kfunc when it carries a DECL_TAG whose name is "kfunc"
    /// or "bpf_kfunc".
    pub(super) kfuncs: HashMap<String, u32>,
    /// Names of subprograms whose ELF symbol carries STV_HIDDEN/STV_INTERNAL
    /// visibility. libbpf rewrites their BTF FUNC linkage from GLOBAL to
    /// STATIC at load (libbpf.c:3552), so the kernel verifies them inline
    /// with the caller's concrete reg types instead of independently with
    /// PTR_MAYBE_NULL-tagged signature args. Mirror that here so callers of
    /// `__weak __hidden` helpers (e.g. libbpf's `bpf_usdt_arg`) skip the
    /// global-subprog override path.
    pub hidden_subprogs: HashSet<String>,
    /// Memoization for `find_special_fields` keyed by type_id. The
    /// recursive DATASEC walk (5f0362e) blew up the per-load cost when
    /// invoked on every map-value access via
    /// `check_btf_fields_access`. BTF is immutable per program, so the
    /// per-type result is safe to cache. `Arc<Mutex>` rather than
    /// `RefCell` because BtfContext must be `Send + Sync + Clone` for
    /// the rayon-parallel sweep dispatcher; the `Arc` makes the cache
    /// shared across clones (which represent the same BTF anyway).
    pub(super) special_fields_cache:
        std::sync::Arc<std::sync::Mutex<HashMap<u32, Vec<SpecialField>>>>,
    /// Parsed `.BTF.ext` records (CO-RE relocations grouped by SEC name).
    /// Populated by [`crate::parsing::btf::parse_btf_ext`] when an ELF
    /// carries a `.BTF.ext` section. Empty for objects without one and
    /// for objects where parsing failed (parse errors are non-fatal).
    /// Foundation only: no resolver wired today (would need vmlinux BTF
    /// or a runtime-supplied target BTF).
    pub btf_ext: Option<super::ext::BtfExt>,
}

/// One variable inside a BTF_KIND_DATASEC.
#[derive(Debug, Clone)]
pub struct DatasecEntry {
    /// BTF type id of the variable (BTF_KIND_VAR). Use
    /// [`BtfContext::var_info`] to resolve it to `(name, target_type_id)`.
    pub var_id: u32,
    /// Byte offset of the variable within the section.
    pub offset: u32,
    /// Size in bytes of the variable.
    pub size: u32,
}

/// One resolved parameter of a struct_ops member's FUNC_PROTO.
///
/// `Scalar` covers integers, enums, floats — anything that lowers
/// to a register-width value the verifier treats as a scalar.
///
/// `TrustedPtr(name)` is a pointer to a named struct/union; the name
/// is the BTF type name (e.g. "sock", "tcp_sock", "task_struct").
/// The entry-state plumbing maps this to
/// `RegType::PtrToBtfId { type_name, flags: TRUSTED }` after interning
/// through a small static table of well-known kernel struct names.
///
/// `OpaquePtr` is a pointer to anything else — function pointers,
/// pointers to primitives, void *. Caller decides whether to widen
/// to a generic UNTRUSTED PtrToBtfId or scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructOpsArg {
    Scalar,
    TrustedPtr(String),
    OpaquePtr,
}

/// Classification of one parameter in a global subprog's BTF FUNC_PROTO.
/// Drives the "global function arg validation" path: caller-side
/// type matching, callee-side R1..R5 entry-state seeding, and the
/// `FWD size cannot be determined` rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalFuncArg {
    /// Integer / enum / float. Caller must pass a scalar; callee
    /// receives a generic `ScalarValue` at entry.
    Scalar,
    /// Pointer to a sized struct/union/scalar with byte size `mem_size`.
    /// Caller may pass any compatible memory pointer; callee receives
    /// `PtrToAllocMemOrNull { mem_size }` and must null-check before
    /// dereferencing — this is what produces the kernel's
    /// "invalid mem access 'mem_or_null'" rejection inside the callee.
    /// `nonnull` is set when the arg carries the `__arg_nonnull` BTF
    /// decl-tag; the kernel strips PTR_MAYBE_NULL from the callee
    /// entry-state (btf.c:7831), so the body sees `PtrToAllocMem`
    /// without needing a null-check.
    PtrToMem { mem_size: u32, nonnull: bool },
    /// Pointer to a recognized BPF context struct (`__sk_buff`,
    /// `xdp_md`, `pt_regs`, ...). Caller must pass `PtrToCtx`; the
    /// callee receives the same. Distinct from `PtrToMem` because the
    /// kernel allows ctx-typed global subprog args without
    /// MAYBE_NULL semantics — the ctx is always non-null.
    PtrToCtx,
    /// Pointer to a forward-declared struct (`struct S;` with no
    /// definition). Size is unknown to BTF, so the kernel rejects
    /// with "reference type('FWD S') size cannot be determined".
    PtrToFwd { name: String },
    /// `void *` or other unresolved pointer target — typically used
    /// with kernel `__arg_ctx` / `__arg_nullable` DECL_TAG
    /// annotations we don't yet parse. Caller accepts any pointer
    /// kind plus NULL; callee receives PtrToCtx (the most common
    /// real meaning) so body access is liberal but not pointer-leaky.
    PermissivePtr,
    /// Pointer to a kernel BTF struct passed with `__arg_trusted`.
    /// Caller must pass `PtrToBtfId` (or `PtrToBtfIdOrNull` if the
    /// arg is also `__arg_nullable`); callee receives the same.
    /// Mirrors kernel's `KF_ARG_PTR_TO_BTF_ID | KF_TRUSTED_ARGS`
    /// validation for global subprog args.
    PtrToBtfIdTrusted { type_name: String, nullable: bool },
    /// Pointer to `struct bpf_dynptr`. Mirrors kernel
    /// `ARG_PTR_TO_DYNPTR | MEM_RDONLY` (btf.c:7784) — caller must
    /// pass a stack pointer to an initialized dynptr; callee body
    /// consumes it via `bpf_dynptr_data`/`_slice`. Distinct from
    /// `PtrToMem{16}` because (a) the slot is `DynptrSlot`, not raw
    /// readable bytes, so the stack-readability check does not apply
    /// and (b) the callee's R is preserved across the call boundary
    /// rather than reseeded as `PtrToAllocMemOrNull`.
    PtrToDynptr,
    /// Arena pointer arg (`__arg_arena` btf_decl_tag = `arg:arena`).
    /// Caller must pass `PtrToArena`; callee receives the same. The
    /// arena address space is sparse-mapped 4GB and the verifier
    /// permits liberal arithmetic on PtrToArena (see
    /// `check_ptr_arithmetic`'s arena fast-path), so this is just a
    /// pass-through arg classification — no MEM_OR_NULL reseed.
    PtrToArena,
}

/// Refine a base `GlobalFuncArg` classification using `__arg_*` decl
/// tags collected from BTF DECL_TAG entries targeting a FUNC's argument
/// (component_idx = arg index). Recognized:
///   - `arg_trusted` → if the base is a struct/empty pointer, switch to
///     `PtrToBtfIdTrusted` (kernel treats it as a kernel BTF id).
///   - `arg_nullable` → marks the argument as MAYBE_NULL on the
///     trusted-ptr variant. No effect on `PtrToCtx`.
///   - `arg_ctx` → upgrade an unresolved/struct pointer to PtrToCtx.
pub(super) fn refine_global_arg_with_tags(
    base: GlobalFuncArg,
    tags: &[&str],
    arg_type_id: u32,
    btf: &BtfContext,
) -> GlobalFuncArg {
    // Kernel encodes these via clang `btf_decl_tag("arg:<kind>")`.
    let trusted = tags.contains(&"arg:trusted");
    let nullable = tags.contains(&"arg:nullable");
    let nonnull = tags.contains(&"arg:nonnull");
    let ctx_tag = tags.contains(&"arg:ctx");
    let arena_tag = tags.contains(&"arg:arena");
    if arena_tag {
        return GlobalFuncArg::PtrToArena;
    }
    if ctx_tag {
        return GlobalFuncArg::PtrToCtx;
    }
    if trusted {
        // Need a struct-typed pointee — pull the name from BTF.
        let type_name = btf
            .pointee_struct_name(arg_type_id)
            .unwrap_or_else(|| "?".to_string());
        return GlobalFuncArg::PtrToBtfIdTrusted {
            type_name,
            nullable,
        };
    }
    if nonnull && let GlobalFuncArg::PtrToMem { mem_size, .. } = base {
        return GlobalFuncArg::PtrToMem {
            mem_size,
            nonnull: true,
        };
    }
    base
}

/// Names of struct types the kernel treats as a BPF program context
/// when used as a pointer arg of a global subprog. Drives the
/// caller-side "PtrToCtx is admissible" check. Mirrors the
/// kernel's per-prog-type ctx struct allowlist (kept loose: any
/// recognized name is accepted regardless of the calling prog kind —
/// a tighter check would require per-prog-type plumbing we defer).
pub(super) fn is_ctx_struct_name(name: &str) -> bool {
    matches!(
        name,
        "__sk_buff"
            | "xdp_md"
            | "pt_regs"
            | "bpf_user_pt_regs_t"
            | "bpf_perf_event_data"
            | "bpf_raw_tracepoint_args"
            | "bpf_sock"
            | "bpf_sock_addr"
            | "bpf_sock_ops"
            | "bpf_sysctl"
            | "sk_msg_md"
            | "sk_reuseport_md"
            | "bpf_sockopt"
            | "bpf_sk_lookup"
    )
}
