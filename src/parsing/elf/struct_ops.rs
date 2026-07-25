//! Recover `subprog_name → (ops_struct_name, member_name)` bindings for
//! BPF_PROG_TYPE_STRUCT_OPS programs.
//!
//! Why: an ELF subprog tagged `SEC("struct_ops")` (bare form, used by
//! `bpf_dctcp.c`/`bpf_cubic.c` and most v6.15-era struct_ops sources)
//! carries no in-source declaration of which ops-struct member it
//! implements. The binding lives in the `.struct_ops` (or
//! `.struct_ops.link`) data section, where each member slot of an
//! initialized ops-struct variable is filled by an ELF relocation
//! pointing at a function symbol. We walk those relocations and use the
//! BTF DATASEC + STRUCT layout to recover the binding.
//!
//! The newer explicit `SEC("struct_ops/<member>")` form names the member
//! in the section string itself; this resolver still produces a binding
//! for those subprogs by walking the same relocations, which keeps the
//! caller logic uniform (one path to reach `resolve_struct_ops_method`).
//!
//! Output is consumed by the entry-state plumbing in the runner
//! (step 4) — it joins each binding with
//! [`crate::parsing::btf::BtfContext::resolve_struct_ops_method`] to
//! type R1..Rn at subprog entry.

use crate::parsing::btf::BtfContext;
use goblin::elf::{Elf, reloc::Reloc};

/// One recovered struct_ops binding.
#[derive(Debug, Clone)]
pub struct StructOpsBinding {
    /// ELF symbol name of the BPF subprogram (e.g. `"bpf_dctcp_init"`).
    pub subprog: String,
    /// Name of the kernel ops struct (e.g. `"tcp_congestion_ops"`).
    pub ops_struct: String,
    /// Name of the member within the ops struct (e.g. `"init"`).
    pub member: String,
}

/// One ops-struct variable inside a `.struct_ops*` data section.
#[derive(Debug, Clone)]
struct OpsVar {
    /// Byte offset within the data section. Sourced from the ELF symbol
    /// table — clang leaves BTF DATASEC offsets at 0 and libbpf patches
    /// them post-link from the symbol table; we do the same.
    offset: u32,
    size: u32,
    /// Name of the kernel ops struct this variable instantiates.
    struct_name: String,
    /// BTF type id of the ops struct (used to translate member offsets
    /// back to member names via `member_name_at_offset`).
    struct_type_id: u32,
}

fn resolve_ops_vars(elf: &Elf<'_>, section_idx: usize, btf: &BtfContext) -> Vec<OpsVar> {
    // Collect ELF symbols pointing into this section. Each symbol gives
    // us the var's name and (st_value) byte offset within the section.
    let mut by_name: std::collections::HashMap<&str, (u32, u32)> = std::collections::HashMap::new();
    for sym in elf.syms.iter() {
        if sym.st_shndx != section_idx {
            continue;
        }
        let name = match elf.strtab.get_at(sym.st_name) {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        by_name.insert(name, (sym.st_value as u32, sym.st_size as u32));
    }

    // Pair each symbol with the matching BTF VAR (by name) to recover the
    // ops-struct type. BTF DATASEC carries the type, ELF symbols carry the
    // offset — neither alone is sufficient.
    let mut out = Vec::new();
    for sec in [".struct_ops", ".struct_ops.link"] {
        let Some(datasec_id) = btf.find_datasec(sec) else {
            continue;
        };
        for entry in btf.datasec_entries(datasec_id) {
            let Some((var_name, struct_type_id)) = btf.var_info(entry.var_id) else {
                continue;
            };
            let Some(&(off, sym_size)) = by_name.get(var_name) else {
                continue;
            };
            let Some(struct_name) = btf.struct_name(struct_type_id) else {
                continue;
            };
            // Prefer the symbol's size; fall back to BTF entry size when
            // clang elides it (ENV_DATASEC sometimes reports 0 for vars).
            let size = if sym_size > 0 { sym_size } else { entry.size };
            out.push(OpsVar {
                offset: off,
                size,
                struct_name: struct_name.to_string(),
                struct_type_id,
            });
        }
    }
    out
}

/// Walk every `.struct_ops` / `.struct_ops.link` data section in the
/// ELF and produce one `StructOpsBinding` per `(member-slot, subprog)`
/// relocation found. Sections that don't exist or carry no relocations
/// are silently skipped — non-struct_ops ELFs return an empty Vec.
pub fn extract_bindings(_bytes: &[u8], elf: &Elf<'_>, btf: &BtfContext) -> Vec<StructOpsBinding> {
    let mut out = Vec::new();
    for sh_idx in 0..elf.section_headers.len() {
        let sh = &elf.section_headers[sh_idx];
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name != ".struct_ops" && name != ".struct_ops.link" {
            continue;
        }

        let vars = resolve_ops_vars(elf, sh_idx, btf);
        if vars.is_empty() {
            continue;
        }

        // Find the relocation section that targets this data section. ELF
        // links the reloc section back to its target via `sh_info`.
        let relocs: Vec<Reloc> = elf
            .shdr_relocs
            .iter()
            .filter(|(rel_sh_idx, _)| {
                elf.section_headers
                    .get(*rel_sh_idx)
                    .map(|rsh| rsh.sh_info as usize == sh_idx)
                    .unwrap_or(false)
            })
            .flat_map(|(_, sec)| sec.iter())
            .collect();
        if relocs.is_empty() {
            continue;
        }

        for r in &relocs {
            let off = r.r_offset as u32;

            // Find which ops-struct variable covers this relocation offset.
            let Some(var) = vars
                .iter()
                .find(|v| off >= v.offset && off < v.offset.saturating_add(v.size))
            else {
                continue;
            };

            let member_offset_in_struct = off - var.offset;
            let Some(member_name) =
                btf.member_name_at_offset(var.struct_type_id, member_offset_in_struct)
            else {
                // Relocation lands on a non-function-pointer slot (e.g. a
                // scalar field like `.flags` or a string like `.name`) —
                // not a struct_ops method binding. Skip silently.
                continue;
            };

            // Resolve the relocation's symbol → subprog name.
            let sym = match elf.syms.get(r.r_sym) {
                Some(s) => s,
                None => continue,
            };
            let Some(sym_name) = elf.strtab.get_at(sym.st_name) else {
                continue;
            };
            if sym_name.is_empty() {
                continue;
            }

            out.push(StructOpsBinding {
                subprog: sym_name.to_string(),
                ops_struct: var.struct_name.clone(),
                member: member_name.to_string(),
            });
        }
    }
    out
}
