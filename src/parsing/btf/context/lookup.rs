//! Low-level BTF lookup primitives: string table reads, modifier peeling,
//! pointer/struct-name resolution, type sizing, kind predicates.

use super::super::types::*;

impl BtfContext {
    /// Public read of an interned BTF string by its byte offset into the
    /// string blob. Returns the C-string up to the first NUL.
    pub fn read_string(&self, offset: u32) -> Option<&str> {
        self.get_string(offset)
    }

    pub(in crate::parsing::btf) fn get_string(&self, offset: u32) -> Option<&str> {
        let start = offset as usize;
        if start >= self.strings.len() {
            return None;
        }
        let end = self.strings[start..].iter().position(|&b| b == 0)? + start;
        std::str::from_utf8(&self.strings[start..end]).ok()
    }

    /// Find a STRUCT (or UNION) BTF type by its declared name. Linear
    /// scan — only called once per struct_ops program at entry-state
    /// setup, so the cost is irrelevant. Returns the BTF type id.
    pub fn find_struct_by_name(&self, name: &str) -> Option<u32> {
        for ty in self.types.values() {
            if !matches!(ty.kind(), BTF_KIND_STRUCT | BTF_KIND_UNION) {
                continue;
            }
            if self.get_string(ty.name_off) == Some(name) {
                return Some(ty.id);
            }
        }
        None
    }

    /// Peel TYPEDEF / CONST / VOLATILE / RESTRICT wrappers and return the
    /// underlying type id. Stops on the first non-wrapper kind. Bounded
    /// to 16 hops as a defensive cycle guard.
    pub fn peel_modifiers(&self, mut type_id: u32) -> u32 {
        for _ in 0..16 {
            let Some(ty) = self.types.get(&type_id) else {
                return type_id;
            };
            match ty.kind() {
                BTF_KIND_TYPEDEF | BTF_KIND_CONST | BTF_KIND_VOLATILE | BTF_KIND_RESTRICT => {
                    type_id = ty.size_or_type;
                }
                _ => return type_id,
            }
        }
        type_id
    }

    /// If `type_id` (after peeling modifiers) is a `PTR -> X` chain,
    /// return `X` (also peeled). Otherwise None.
    pub fn pointee(&self, type_id: u32) -> Option<u32> {
        let id = self.peel_modifiers(type_id);
        let ty = self.types.get(&id)?;
        if ty.kind() != BTF_KIND_PTR {
            return None;
        }
        Some(self.peel_modifiers(ty.size_or_type))
    }

    /// Return the declared name of a STRUCT / UNION type, peeling any
    /// modifier wrappers first. Returns None for unnamed types or
    /// non-struct kinds.
    pub fn struct_name(&self, type_id: u32) -> Option<&str> {
        let id = self.peel_modifiers(type_id);
        let ty = self.types.get(&id)?;
        if !matches!(ty.kind(), BTF_KIND_STRUCT | BTF_KIND_UNION) {
            return None;
        }
        self.get_string(ty.name_off)
    }

    /// Like `struct_name`, but also returns the declared name for
    /// BTF_KIND_FWD types (forward declarations of opaque kernel
    /// structs). Programs that hold typed `__kptr` fields to opaque
    /// kernel types (e.g. `struct bpf_cpumask __kptr *`) carry only a
    /// FWD entry for the inner type — the full struct definition lives
    /// in vmlinux BTF, not the program's BTF. Validators that key off
    /// the pointee type name (e.g. cpumask kfuncs accepting a kptr to
    /// `bpf_cpumask`) need this fallback.
    pub fn struct_or_fwd_name(&self, type_id: u32) -> Option<&str> {
        let id = self.peel_modifiers(type_id);
        let ty = self.types.get(&id)?;
        if !matches!(ty.kind(), BTF_KIND_STRUCT | BTF_KIND_UNION | BTF_KIND_FWD) {
            return None;
        }
        self.get_string(ty.name_off)
    }

    /// Resolved byte size of a type, peeling modifiers/typedefs/VARs.
    /// Returns 0 for types we don't understand (FUNC_PROTO, FWD, …)
    /// or on cyclic chains. Mirrors `get_resolved_size` in the raw-Vec
    /// path but operates on `self.types`.
    pub fn type_size_bytes(&self, type_id: u32) -> u32 {
        self.type_size_bytes_depth(type_id, 0)
    }

    /// True if the struct (or any nested struct member) contains a
    /// PTR-typed field. Used by `bpf_percpu_obj_new` validation to
    /// reject pointee structs that would carry stale pointers across
    /// percpu copies (kernel "type ID argument must be of a struct of
    /// scalars"). Walks one level into nested structs/unions; arrays
    /// of scalars are fine, arrays of pointers are not.
    pub fn struct_contains_pointer(&self, type_id: u32) -> bool {
        self.struct_contains_pointer_depth(type_id, 0)
    }

    fn struct_contains_pointer_depth(&self, type_id: u32, depth: u32) -> bool {
        if depth > 8 {
            return false;
        }
        let id = self.peel_modifiers(type_id);
        let Some(ty) = self.types.get(&id) else {
            return false;
        };
        match ty.kind() {
            BTF_KIND_PTR => true,
            BTF_KIND_STRUCT | BTF_KIND_UNION => ty
                .members
                .iter()
                .any(|m| self.struct_contains_pointer_depth(m.type_id, depth + 1)),
            BTF_KIND_ARRAY => ty
                .members
                .first()
                .map(|m| self.struct_contains_pointer_depth(m.type_id, depth + 1))
                .unwrap_or(false),
            _ => false,
        }
    }

    pub(in crate::parsing::btf) fn type_size_bytes_depth(&self, type_id: u32, depth: u32) -> u32 {
        if depth > 16 {
            return 0;
        }
        let Some(t) = self.types.get(&type_id) else {
            return 0;
        };
        match t.kind() {
            BTF_KIND_INT | BTF_KIND_ENUM | BTF_KIND_ENUM64 | BTF_KIND_FLOAT | BTF_KIND_STRUCT
            | BTF_KIND_UNION | BTF_KIND_DATASEC => t.size_or_type,
            BTF_KIND_PTR => 8,
            BTF_KIND_ARRAY => {
                if let Some(m) = t.members.first() {
                    let elem_size = self.type_size_bytes_depth(m.type_id, depth + 1);
                    elem_size.saturating_mul(m.offset) // m.offset = nelems
                } else {
                    0
                }
            }
            BTF_KIND_TYPEDEF | BTF_KIND_CONST | BTF_KIND_VOLATILE | BTF_KIND_RESTRICT
            | BTF_KIND_VAR | BTF_KIND_TYPE_TAG => {
                self.type_size_bytes_depth(t.size_or_type, depth + 1)
            }
            _ => 0,
        }
    }

    /// Walk a type id past TYPEDEF/CONST/VOLATILE/RESTRICT modifiers and
    /// return true if the underlying kind is an integer-class scalar
    /// (INT / ENUM / ENUM64). Used to validate exception-callback
    /// signatures and similar constraints. False for void (id 0),
    /// pointers, structs, etc.
    pub fn is_integer_scalar(&self, type_id: u32) -> bool {
        if type_id == 0 {
            return false;
        }
        let id = self.peel_modifiers(type_id);
        match self.types.get(&id) {
            Some(ty) => matches!(ty.kind(), BTF_KIND_INT | BTF_KIND_ENUM | BTF_KIND_ENUM64),
            None => false,
        }
    }
}
