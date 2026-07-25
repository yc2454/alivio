//! BTF_KIND_DATASEC and BTF_KIND_VAR access, plus the
//! ELF-driven offset patcher that mirrors libbpf's post-link rewrite.

use std::collections::HashMap;

use super::super::types::*;

impl BtfContext {
    /// Patch DATASEC member offsets from an ELF-symbol name→offset map.
    /// clang emits BTF DATASEC entries with `offset = 0` for every var;
    /// libbpf rewrites them post-link from the symbol table. We do the
    /// same: for each DATASEC member whose VAR resolves to a name found
    /// in `name_to_offset`, overwrite the entry's offset. Members not in
    /// the map (or whose VAR has no name) are left untouched.
    ///
    /// Without this, `find_special_fields` on a `.bss.<name>` DATASEC
    /// reports every var at offset 0, which fails the offset-match
    /// check in MapValueSpecial validators (spin_lock at offset 32 vs
    /// ".bss.A reports SpinLock at offset 0").
    pub fn patch_datasec_offsets(&mut self, name_to_offset: &HashMap<String, u32>) {
        // First, collect (var_id → name) from VAR entries so we don't
        // borrow self both mutably and immutably in the loop below.
        let var_names: HashMap<u32, String> = self
            .types
            .values()
            .filter(|t| t.kind() == BTF_KIND_VAR)
            .filter_map(|t| self.get_string(t.name_off).map(|n| (t.id, n.to_string())))
            .collect();
        for ty in self.types.values_mut() {
            if ty.kind() != BTF_KIND_DATASEC {
                continue;
            }
            for member in ty.members.iter_mut() {
                let Some(var_name) = var_names.get(&member.type_id) else {
                    continue;
                };
                if let Some(&off) = name_to_offset.get(var_name) {
                    member.offset = off;
                }
            }
        }
    }

    /// Find a BTF_KIND_DATASEC by section name (e.g. ".struct_ops",
    /// ".struct_ops.link", ".rodata", ".bss"). Returns the BTF type id.
    pub fn find_datasec(&self, section_name: &str) -> Option<u32> {
        for ty in self.types.values() {
            if ty.kind() != BTF_KIND_DATASEC {
                continue;
            }
            if self.get_string(ty.name_off) == Some(section_name) {
                return Some(ty.id);
            }
        }
        None
    }

    /// Iterate the variables of a DATASEC. Returns an empty iterator if the
    /// id isn't a DATASEC.
    pub fn datasec_entries(&self, datasec_id: u32) -> Vec<DatasecEntry> {
        let Some(ty) = self.types.get(&datasec_id) else {
            return Vec::new();
        };
        if ty.kind() != BTF_KIND_DATASEC {
            return Vec::new();
        }
        ty.members
            .iter()
            .map(|m| DatasecEntry {
                var_id: m.type_id,
                offset: m.offset,
                size: m.name_off, // we packed size into name_off — see parse_btf
            })
            .collect()
    }

    /// Resolve a BTF_KIND_VAR into `(var_name, target_type_id)`. Returns None
    /// if the id isn't a VAR.
    pub fn var_info(&self, var_id: u32) -> Option<(&str, u32)> {
        let ty = self.types.get(&var_id)?;
        if ty.kind() != BTF_KIND_VAR {
            return None;
        }
        let name = self.get_string(ty.name_off)?;
        Some((name, ty.size_or_type))
    }

    /// Classify a `__ksym` extern's type chain (the var's `size_or_type`
    /// from `.ksyms` DATASEC) into `(struct_name, is_percpu)`.
    ///
    /// Walks past TYPEDEF/CONST/VOLATILE/RESTRICT modifiers, capturing any
    /// `percpu` TYPE_TAG seen. Terminates at STRUCT/UNION/FWD (returning
    /// the name) or any other terminal kind (returning `None` for
    /// `struct_name` — typeless / primitive ksyms).
    pub fn classify_ksym_type(&self, start_id: u32) -> (Option<String>, bool) {
        use super::super::types::{
            BTF_KIND_CONST, BTF_KIND_FWD, BTF_KIND_RESTRICT, BTF_KIND_STRUCT, BTF_KIND_TYPE_TAG,
            BTF_KIND_TYPEDEF, BTF_KIND_UNION, BTF_KIND_VOLATILE,
        };
        let mut id = start_id;
        let mut is_percpu = false;
        for _ in 0..16 {
            let Some(t) = self.types.get(&id) else { break };
            match t.kind() {
                BTF_KIND_TYPEDEF | BTF_KIND_CONST | BTF_KIND_VOLATILE | BTF_KIND_RESTRICT => {
                    id = t.size_or_type;
                }
                BTF_KIND_TYPE_TAG => {
                    if self.get_string(t.name_off) == Some("percpu") {
                        is_percpu = true;
                    }
                    id = t.size_or_type;
                }
                BTF_KIND_STRUCT | BTF_KIND_UNION | BTF_KIND_FWD => {
                    return (
                        self.get_string(t.name_off).map(|s| s.to_string()),
                        is_percpu,
                    );
                }
                _ => return (None, is_percpu),
            }
        }
        (None, is_percpu)
    }
}
