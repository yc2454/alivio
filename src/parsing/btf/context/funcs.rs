//! struct_ops member resolution, global subprog argument classification,
//! and exception-callback signature validation. All operate against the
//! parsed FUNC / FUNC_PROTO entries on `BtfContext`.

use super::super::types::*;

impl BtfContext {
    /// Resolve the parameter list of a single struct_ops member.
    ///
    /// Walks `struct <struct_name> { ... <member_name>; ... }`, finds the
    /// member, peels its `PTR -> FUNC_PROTO` chain, and returns one
    /// `StructOpsArg` per parameter.
    ///
    /// Returns None if any of the following are true:
    ///   * the struct isn't in BTF,
    ///   * no member matches `member_name`,
    ///   * the member doesn't resolve to a `PTR -> FUNC_PROTO`.
    ///
    /// Why a method-by-method resolver instead of pre-computing all of
    /// them: only programs whose section is `SEC("struct_ops/...")` need
    /// this, and there are few of them per ELF — the linear cost is
    /// negligible against the verifier itself.
    pub fn resolve_struct_ops_method(
        &self,
        struct_name: &str,
        member_name: &str,
    ) -> Option<Vec<StructOpsArg>> {
        let struct_id = self.find_struct_by_name(struct_name)?;
        let struct_ty = self.types.get(&struct_id)?;

        let member = struct_ty
            .members
            .iter()
            .find(|m| self.get_string(m.name_off) == Some(member_name))?;

        // Member type is `PTR -> FUNC_PROTO`. Peel the PTR.
        let func_proto_id = self.pointee(member.type_id)?;
        let func_proto = self.types.get(&func_proto_id)?;
        if func_proto.kind() != BTF_KIND_FUNC_PROTO {
            return None;
        }

        let args = func_proto
            .members
            .iter()
            .map(|p| self.classify_param(p.type_id))
            .collect();
        Some(args)
    }

    /// Does the named struct_ops member return void? Returns None if the
    /// member or its FUNC_PROTO can't be resolved. The kernel verifier
    /// relaxes the "R0 must be initialized at exit" check for void
    /// return types, so the runner needs to know this to type the exit
    /// state correctly.
    pub fn struct_ops_method_returns_void(
        &self,
        struct_name: &str,
        member_name: &str,
    ) -> Option<bool> {
        let struct_id = self.find_struct_by_name(struct_name)?;
        let struct_ty = self.types.get(&struct_id)?;
        let member = struct_ty
            .members
            .iter()
            .find(|m| self.get_string(m.name_off) == Some(member_name))?;
        let proto_id = self.pointee(member.type_id)?;
        let proto = self.types.get(&proto_id)?;
        if proto.kind() != BTF_KIND_FUNC_PROTO {
            return None;
        }
        // BTF encodes void return as type id 0.
        Some(proto.size_or_type == 0)
    }

    /// Classification of a global-subprog argument from BTF, used to
    /// emit the kernel's "Caller passes invalid args" / "FWD size
    /// cannot be determined" / "expected ..." errors and to seed the
    /// callee's R1..R5 with declared types when verifying its body.
    ///
    /// Distinct from `StructOpsArg`: struct_ops's TrustedPtr is a
    /// kernel-typed pointer, whereas a global subprog's pointer arg is
    /// the kernel verifier's `PTR_TO_MEM | PTR_MAYBE_NULL` — bounded
    /// by the pointee's BTF size, callee must null-check.
    pub fn resolve_global_func_args(&self, func_name: &str) -> Option<Vec<GlobalFuncArg>> {
        let (func_id, func_ty) = self.types.iter().find(|(_, ty)| {
            ty.kind() == BTF_KIND_FUNC && self.get_string(ty.name_off) == Some(func_name)
        })?;
        let func_id = *func_id;
        let proto = self.types.get(&func_ty.size_or_type)?;
        if proto.kind() != BTF_KIND_FUNC_PROTO {
            return None;
        }

        // Per-arg decl tags (e.g. `__arg_trusted`, `__arg_nullable`,
        // `__arg_ctx`) target the FUNC btf_id with `component_idx`
        // = arg index. Collect tags per index up front.
        let mut tags_per_arg: std::collections::HashMap<i32, Vec<&str>> =
            std::collections::HashMap::new();
        for tag in self.decl_tags_for(func_id) {
            if tag.component_idx >= 0 {
                tags_per_arg
                    .entry(tag.component_idx)
                    .or_default()
                    .push(tag.name.as_str());
            }
        }

        Some(
            proto
                .members
                .iter()
                .enumerate()
                .map(|(idx, p)| {
                    let base = self.classify_global_func_arg(p.type_id);
                    let empty = Vec::new();
                    let tags = tags_per_arg.get(&(idx as i32)).unwrap_or(&empty);
                    refine_global_arg_with_tags(base, tags, p.type_id, self)
                })
                .collect(),
        )
    }

    /// Resolve the type-name for a BTF type used as a pointee. Strips
    /// modifiers (CONST/VOLATILE/RESTRICT/TYPEDEF) and returns the
    /// underlying STRUCT/UNION name when possible. Used by
    /// `refine_global_arg_with_tags` to populate `PtrToBtfIdTrusted`.
    pub(in crate::parsing::btf) fn pointee_struct_name(&self, ptr_type_id: u32) -> Option<String> {
        let id = self.peel_modifiers(ptr_type_id);
        let ty = self.types.get(&id)?;
        if ty.kind() != BTF_KIND_PTR {
            return None;
        }
        let pid = self.peel_modifiers(ty.size_or_type);
        let pty = self.types.get(&pid)?;
        Some(self.get_string(pty.name_off).unwrap_or("?").to_string())
    }

    fn classify_global_func_arg(&self, type_id: u32) -> GlobalFuncArg {
        let id = self.peel_modifiers(type_id);
        let Some(ty) = self.types.get(&id) else {
            return GlobalFuncArg::Scalar;
        };
        match ty.kind() {
            BTF_KIND_INT | BTF_KIND_ENUM | BTF_KIND_ENUM64 | BTF_KIND_FLOAT => {
                GlobalFuncArg::Scalar
            }
            BTF_KIND_PTR => {
                let pointee_id = self.peel_modifiers(ty.size_or_type);
                let Some(pointee) = self.types.get(&pointee_id) else {
                    // Unresolved pointee — typically `void *`, also
                    // possible for opaque kernel types we don't have
                    // BTF for. The kernel relies on DECL_TAG
                    // annotations (`__arg_ctx`, `__arg_nullable`,
                    // ...) to refine; without those we can't
                    // distinguish ctx-typed from mem-typed `void *`.
                    // Be permissive at the caller boundary: a
                    // PermissivePtr accepts ctx, any mem pointer, or
                    // NULL. Body verification loses some checks but
                    // we don't false-reject legitimate `void *ctx`
                    // global subprogs (test_global_func_ctx_args).
                    return GlobalFuncArg::PermissivePtr;
                };
                match pointee.kind() {
                    // FWD: struct declared but not defined — the kernel
                    // can't determine its size, which is what test
                    // global_func14 asserts.
                    BTF_KIND_FWD => GlobalFuncArg::PtrToFwd {
                        name: self.get_string(pointee.name_off).unwrap_or("?").to_string(),
                    },
                    BTF_KIND_STRUCT | BTF_KIND_UNION => {
                        let pname = self.get_string(pointee.name_off).unwrap_or("");
                        if is_ctx_struct_name(pname) {
                            GlobalFuncArg::PtrToCtx
                        } else if pname == "bpf_dynptr" {
                            GlobalFuncArg::PtrToDynptr
                        } else {
                            GlobalFuncArg::PtrToMem {
                                mem_size: pointee.size_or_type,
                                nonnull: false,
                            }
                        }
                    }
                    BTF_KIND_INT | BTF_KIND_ENUM | BTF_KIND_ENUM64 | BTF_KIND_FLOAT => {
                        GlobalFuncArg::PtrToMem {
                            mem_size: pointee.size_or_type,
                            nonnull: false,
                        }
                    }
                    // `int (*arr)[10]` etc.: pointer to a fixed-size array.
                    // ARRAY's parsed members[0] carries (elem_type, nelems);
                    // total mem_size = elem_size * nelems. Peel modifiers on
                    // the elem so typedef'd elem types resolve. Required for
                    // `test_global_func9` / `test_global_func16`'s
                    // `quux(int (*arr)[10])` callee body to see R1 as a
                    // 40-byte mem region.
                    BTF_KIND_ARRAY => {
                        let arr = pointee.members.first();
                        let mem_size = arr
                            .map(|m| {
                                let elem_id = self.peel_modifiers(m.type_id);
                                let elem_size = self
                                    .types
                                    .get(&elem_id)
                                    .map(|t| t.size_or_type)
                                    .unwrap_or(0);
                                elem_size.saturating_mul(m.offset)
                            })
                            .unwrap_or(0);
                        GlobalFuncArg::PtrToMem {
                            mem_size,
                            nonnull: false,
                        }
                    }
                    // Pointer-to-pointer (e.g. `struct S **s`): kernel
                    // treats as ARG_PTR_TO_MEM with mem_size = sizeof(void*)
                    // = 8. Closes test_global_func_args::test_cls — `baz`
                    // does `*s = 0` (8-byte store at R1+0).
                    BTF_KIND_PTR => GlobalFuncArg::PtrToMem {
                        mem_size: 8,
                        nonnull: false,
                    },
                    _ => GlobalFuncArg::PtrToMem {
                        mem_size: 0,
                        nonnull: false,
                    },
                }
            }
            _ => GlobalFuncArg::Scalar,
        }
    }

    /// Returns true iff a BTF_KIND_FUNC by this name has GLOBAL linkage
    /// (vs STATIC or EXTERN). Encoded in FUNC.info bits 0..16
    /// (`BTF_FUNC_GLOBAL = 1`). The kernel verifies global subprogs
    /// independently against their declared signature; static subprogs
    /// inherit the caller's concrete types.
    pub fn is_global_func(&self, func_name: &str) -> bool {
        // libbpf demotes hidden-visibility weak/global subprogs to STATIC
        // before kernel load (libbpf.c:3552) so the kernel verifies them
        // inline. Treat them as static here too.
        if self.hidden_subprogs.contains(func_name) {
            return false;
        }
        let Some(func_ty) = self.types.values().find(|ty| {
            ty.kind() == BTF_KIND_FUNC && self.get_string(ty.name_off) == Some(func_name)
        }) else {
            return false;
        };
        (func_ty.info & 0xffff) == 1
    }

    /// True if the named function's declared return type is `void`
    /// (BTF type id 0 in the FUNC_PROTO `size_or_type`). Used to
    /// reject global subprogs declared with a void return —
    /// "function 'foo' doesn't return scalar".
    pub fn func_returns_void(&self, func_name: &str) -> bool {
        let Some(func_ty) = self.types.values().find(|ty| {
            ty.kind() == BTF_KIND_FUNC && self.get_string(ty.name_off) == Some(func_name)
        }) else {
            return false;
        };
        let Some(proto) = self.types.get(&func_ty.size_or_type) else {
            return false;
        };
        proto.kind() == BTF_KIND_FUNC_PROTO && proto.size_or_type == 0
    }

    /// btf_id of the BTF_KIND_FUNC entry whose declared name is `func_name`,
    /// or None if no such FUNC exists. Linear scan — only invoked at load
    /// time per analyzed program.
    pub fn find_func_id_by_name(&self, func_name: &str) -> Option<u32> {
        self.types
            .values()
            .find(|ty| {
                ty.kind() == BTF_KIND_FUNC && self.get_string(ty.name_off) == Some(func_name)
            })
            .map(|ty| ty.id)
    }

    /// Returns the cb-name strings of every `exception_callback:<cb>` decl
    /// tag whose target FUNC is `main_func_name`. libbpf encodes
    /// `__exception_cb(cb)` as a DECL_TAG with name string
    /// `"exception_callback:<cb>"` attached to the main subprog FUNC.
    /// More than one entry indicates a duplicate-tag error
    /// (kernel: "multiple exception callback tags for main subprog").
    pub fn exception_callback_tags(&self, main_func_name: &str) -> Vec<String> {
        const PREFIX: &str = "exception_callback:";
        let Some(func_id) = self.find_func_id_by_name(main_func_name) else {
            return Vec::new();
        };
        self.decl_tags
            .iter()
            .filter(|t| t.target_type_id == func_id && t.name.starts_with(PREFIX))
            .map(|t| t.name[PREFIX.len()..].to_string())
            .collect()
    }

    /// Validate a registered exception-callback's BTF signature.
    /// Returns Err with the kernel's exact diagnostic string if the
    /// callback's FUNC_PROTO doesn't match the kernel's contract:
    ///   * return type must be a scalar integer (kernel:
    ///     "Global function <name>() doesn't return scalar.")
    ///   * exactly one parameter of integer type (kernel:
    ///     "exception cb only supports single integer argument")
    ///
    /// Returns Ok(()) when both checks pass, or when the cb FUNC isn't
    /// in BTF (deferred to whatever path produces the missing-func
    /// error elsewhere).
    pub fn validate_exception_cb_signature(&self, cb_name: &str) -> Result<(), String> {
        let Some(func_ty) = self
            .types
            .values()
            .find(|ty| ty.kind() == BTF_KIND_FUNC && self.get_string(ty.name_off) == Some(cb_name))
        else {
            return Ok(());
        };
        let Some(proto) = self.types.get(&func_ty.size_or_type) else {
            return Ok(());
        };
        if proto.kind() != BTF_KIND_FUNC_PROTO {
            return Ok(());
        }
        // Kernel checks return type first: void or non-scalar return →
        // "Global function ... doesn't return scalar."
        if !self.is_integer_scalar(proto.size_or_type) {
            return Err(format!(
                "Global function {}() doesn't return scalar.",
                cb_name
            ));
        }
        if proto.members.len() != 1 || !self.is_integer_scalar(proto.members[0].type_id) {
            return Err("exception cb only supports single integer argument".to_string());
        }
        Ok(())
    }

    /// Resolve a subprog's parameter list directly from its BTF FUNC entry.
    ///
    /// clang -target bpf emits a `BTF_KIND_FUNC` for every defined function
    /// in the source, naming it and pointing at the FUNC_PROTO that captured
    /// its declared signature. For struct_ops method implementations the
    /// declared signature matches the ops-struct member's function pointer
    /// type, so this gives us the same answer as walking
    /// `<ops_struct>.<member>` — without needing to know which member the
    /// subprog is bound to. The binding lives in the `.struct_ops`
    /// relocation table; resolving via the FUNC entry sidesteps that
    /// dependency entirely.
    ///
    /// Returns None if no FUNC by that name exists or it doesn't point at
    /// a FUNC_PROTO.
    pub fn resolve_func_args(&self, func_name: &str) -> Option<Vec<StructOpsArg>> {
        let func_ty = self.types.values().find(|ty| {
            ty.kind() == BTF_KIND_FUNC && self.get_string(ty.name_off) == Some(func_name)
        })?;
        // FUNC.size_or_type is the FUNC_PROTO btf_id.
        let proto = self.types.get(&func_ty.size_or_type)?;
        if proto.kind() != BTF_KIND_FUNC_PROTO {
            return None;
        }
        Some(
            proto
                .members
                .iter()
                .map(|p| self.classify_param(p.type_id))
                .collect(),
        )
    }

    fn classify_param(&self, type_id: u32) -> StructOpsArg {
        let id = self.peel_modifiers(type_id);
        let Some(ty) = self.types.get(&id) else {
            return StructOpsArg::Scalar;
        };
        match ty.kind() {
            BTF_KIND_PTR => match self.struct_name(ty.size_or_type) {
                Some(name) => StructOpsArg::TrustedPtr(name.to_string()),
                None => StructOpsArg::OpaquePtr,
            },
            BTF_KIND_INT | BTF_KIND_ENUM | BTF_KIND_ENUM64 | BTF_KIND_FLOAT => StructOpsArg::Scalar,
            _ => StructOpsArg::Scalar,
        }
    }
}
