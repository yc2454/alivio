use crate::ast::{Program, ProgramKind};
use crate::parsing::bpf_to_ast;
use crate::parsing::elf::{
    BpfMapDef, RelocInfo, combine_function_with_subprogs, combine_program_with_subprogs,
    discover_bpf_call_targets,
};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub const OBJ_PROG_TYPE_JSON: &str = "./obj_prog_type.json";

type RawJsonMap = HashMap<String, Option<String>>;

/// Load a Program from an ELF section by:
///   ELF -> bytes -> RawBpfInsn -> Program (via bpf_to_ast).
/// Returns Ok(Program) on success, Err(String) on failure.
pub fn try_load_program_from_elf(
    path: &str,
    section: &str,
    pc_to_reloc: Option<&HashMap<usize, crate::parsing::elf::RelocInfo>>,
) -> Result<Program, String> {
    let bytes = crate::parsing::elf::prog::load_bpf_insn_stream_section(path, section)
        .map_err(|e| format!("Failed to load ELF section '{}': {:?}", section, e))?;

    let mut raw_insns = crate::parsing::bpf_insn::decode_insns(&bytes);

    // Apply relocations if provided
    if let Some(relocs) = pc_to_reloc {
        crate::parsing::elf::reloc::apply_relocs(&mut raw_insns, relocs);
    }

    println!(
        "Loaded section '{}' from '{}': {} bytes, {} instructions",
        section,
        path,
        bytes.len(),
        raw_insns.len()
    );

    bpf_to_ast::lower_raw_to_program(&raw_insns).map_err(|e| {
        format!(
            "Lowering ELF → AST failed at pc {} (opcode 0x{:02x}): {}",
            e.pc, e.code, e.msg
        )
    })
}

/// Load a Program for a specific function within an ELF section.
/// Uses STT_FUNC symbol information to extract only that function's bytes.
pub fn try_load_function_from_elf(
    path: &str,
    section: &str,
    func_name: &str,
    pc_to_reloc: Option<&HashMap<usize, crate::parsing::elf::RelocInfo>>,
) -> Result<Program, String> {
    let bytes =
        crate::parsing::elf::prog::load_function_bytes(path, section, func_name).map_err(|e| {
            format!(
                "Failed to load function '{}' from '{}': {:?}",
                func_name, section, e
            )
        })?;

    let mut raw_insns = crate::parsing::bpf_insn::decode_insns(&bytes);

    // Apply relocations if provided
    // Note: relocations need to be adjusted for function offset
    if let Some(relocs) = pc_to_reloc {
        crate::parsing::elf::reloc::apply_relocs(&mut raw_insns, relocs);
    }

    println!(
        "Loaded function '{}' from section '{}': {} bytes, {} instructions",
        func_name,
        section,
        bytes.len(),
        raw_insns.len()
    );

    bpf_to_ast::lower_raw_to_program(&raw_insns).map_err(|e| {
        format!(
            "Lowering ELF → AST failed at pc {} (opcode 0x{:02x}): {}",
            e.pc, e.code, e.msg
        )
    })
}

/// Load a Program from an ELF section, combining with any cross-section subprograms.
/// If the section has cross-section calls, subprograms are appended and call targets fixed.
/// Returns (Program, relocations) on success.
pub fn try_load_combined_program_from_elf(
    path: &str,
    section: &str,
    maps: &[BpfMapDef],
) -> Result<(Program, HashMap<usize, RelocInfo>), String> {
    // Check if section has cross-section calls
    let cross_section_targets = discover_bpf_call_targets(path, section)
        .map_err(|e| format!("Failed to discover BPF call targets: {:?}", e))?;

    if cross_section_targets.is_empty() {
        // No cross-section calls - use existing behavior
        let pc_to_reloc =
            crate::parsing::elf::reloc::load_relocations(path, maps, section).unwrap_or_default();
        let prog = try_load_program_from_elf(path, section, Some(&pc_to_reloc))?;
        return Ok((prog, pc_to_reloc));
    }

    // Has cross-section calls - combine program with subprograms
    println!(
        "Section '{}' has {} cross-section call target(s), combining with subprograms",
        section,
        cross_section_targets.len()
    );
    for target in &cross_section_targets {
        println!(
            "  -> {}::{} (offset {}, size {})",
            target.section, target.func_name, target.offset_in_section, target.size
        );
    }

    let combined = combine_program_with_subprogs(path, maps, section)
        .map_err(|e| format!("Failed to combine program with subprogs: {:?}", e))?;

    println!(
        "Combined program: {} instructions, {} subprograms appended",
        combined.raw_insns.len(),
        combined.func_offsets.len()
    );
    for (name, pc) in &combined.func_offsets {
        println!("  Function '{}' at PC {}", name, pc);
    }

    let prog = bpf_to_ast::lower_raw_to_program(&combined.raw_insns).map_err(|e| {
        format!(
            "Lowering combined ELF → AST failed at pc {} (opcode 0x{:02x}): {}",
            e.pc, e.code, e.msg
        )
    })?;

    Ok((prog, combined.pc_to_reloc))
}

/// CO-RE-aware variant: when `core_relo_ctx` is `Some((program_btf,
/// target_btf))`, applies CO-RE relocations from `program_btf.btf_ext`
/// to the entry section's raw instructions BEFORE lowering to AST.
/// Mirrors libbpf's `bpf_object__relocate_core` (`tools/lib/bpf/libbpf.c`
/// → `tools/lib/bpf/relo_core.c::bpf_core_apply_relo_insn`). Only the
/// entry section's relos are applied; cross-section subprog relos are
/// not.
pub fn try_load_function_with_subprogs_from_elf_with_relo(
    path: &str,
    section: &str,
    func_name: &str,
    maps: &[BpfMapDef],
    extra_roots: &[(String, String)],
    core_relo_ctx: Option<(&crate::parsing::btf::BtfContext, &crate::parsing::btf::BtfContext)>,
) -> Result<(Program, HashMap<usize, RelocInfo>, HashMap<String, usize>), String> {
    let mut combined =
        combine_function_with_subprogs(path, maps, section, func_name, extra_roots)
            .map_err(|e| format!("Failed to combine function with subprogs: {:?}", e))?;

    if combined.raw_insns.is_empty() {
        return Err(format!(
            "Function '{}' not found in section '{}'",
            func_name, section
        ));
    }

    if let Some((program_btf, target_btf)) = core_relo_ctx
        && let Some(ext) = program_btf.btf_ext.as_ref()
    {
        // Build a `(section_byte_off, size) → function_name` map for
        // every section this combined load knows about. A CO-RE relo
        // carries its insn_off as a byte offset within its CONTAINING
        // ELF section (not the combined stream). We map it to the
        // combined insn index by:
        //   1. find which function (in `combined.func_offsets`) the
        //      byte offset falls inside;
        //   2. translate to combined PC =
        //      `func_offsets[func] + (insn_off - func.section_offset) / 8`.
        // Relos whose insn_off doesn't land in any combined function
        // are skipped (the kernel would also skip them when loading
        // just this entry function — they belong to siblings).
        use std::collections::HashMap;
        let mut sec_to_funcs: HashMap<&str, Vec<crate::parsing::elf::prog::BpfFuncInfo>> =
            HashMap::new();
        for sec_name in ext.core_relos_by_section.iter().map(|(s, _)| s.as_str()) {
            if let Ok(funcs) = crate::parsing::elf::prog::get_functions_in_section(path, sec_name) {
                sec_to_funcs.insert(sec_name, funcs);
            }
        }
        let mut total_applied = 0u32;
        let mut total_no_op = 0u32;
        let mut total_skipped_oof = 0u32;
        let mut total_unsupported = 0u32;
        for (sec_name, relos) in &ext.core_relos_by_section {
            let funcs = match sec_to_funcs.get(sec_name.as_str()) {
                Some(v) => v,
                None => continue,
            };
            let stats = crate::parsing::btf::apply_core_relos(
                program_btf,
                target_btf,
                relos,
                &mut combined.raw_insns,
                |relo_byte_off| {
                    let relo_off = relo_byte_off as usize;
                    let f = funcs
                        .iter()
                        .find(|f| relo_off >= f.offset && relo_off < f.offset + f.size)?;
                    let func_pc = *combined.func_offsets.get(&f.name)?;
                    let in_func_byte = relo_off - f.offset;
                    Some(func_pc + in_func_byte / 8)
                },
            );
            total_applied += stats.enum_exists_applied + stats.field_exists_applied;
            total_no_op += stats.no_op;
            total_skipped_oof += stats.enum_exists_skipped + stats.field_exists_skipped;
            total_unsupported += stats.unsupported_kind;
        }
        if total_applied + total_skipped_oof + total_unsupported > 0 {
            println!(
                "[co-re] {}/{}: applied={} (no_op={}) skipped_oof={} unsupported={}",
                section, func_name, total_applied, total_no_op,
                total_skipped_oof, total_unsupported
            );
        }
    }

    let prog = bpf_to_ast::lower_raw_to_program(&combined.raw_insns).map_err(|e| {
        format!(
            "Lowering combined ELF → AST failed at pc {} (opcode 0x{:02x}): {}",
            e.pc, e.code, e.msg
        )
    })?;

    Ok((prog, combined.pc_to_reloc, combined.func_offsets))
}

/// Lookup program kind for a single object file.
/// - `obj_path` may be a full path; we try exact match, then basename.
/// - Missing key or null => Unknown.
pub fn program_kind_for_object(obj_path: &Path) -> Result<ProgramKind> {
    let json_str = fs::read_to_string(OBJ_PROG_TYPE_JSON)
        .with_context(|| format!("failed to read {}", OBJ_PROG_TYPE_JSON))?;

    let raw: RawJsonMap =
        serde_json::from_str(&json_str).context("failed to parse obj_prog_type.json")?;

    let key_exact = obj_path.to_string_lossy();
    let key_base = obj_path
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_else(|| key_exact.clone());

    let opt_label = raw
        .get(key_exact.as_ref())
        .or_else(|| raw.get(key_base.as_ref()))
        .or_else(|| {
            // Fuzzy match: if an entry ends with key_base, use it.
            // This handles clang-18_-O1_bpf_lxc.o vs bpf_lxc.o
            raw.iter()
                .find(|(k, _)| k.ends_with(key_base.as_ref()))
                .map(|(_, v)| v)
        });

    match opt_label {
        Some(Some(label)) => Ok(ProgramKind::from_section(label)),
        _ => Err(anyhow::anyhow!(
            "program kind not found for object {:?}",
            obj_path
        )),
    }
}
