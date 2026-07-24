use anyhow::Result;
use goblin::elf::{Elf, sym};
use std::fs;
use std::path::Path;

use super::types::RawBpfProgram;

/// Information about a BPF function within a section
#[derive(Debug, Clone)]
pub struct BpfFuncInfo {
    pub name: String,
    /// Offset within the section (in bytes)
    pub offset: usize,
    /// Size of the function (in bytes)
    pub size: usize,
}

pub fn load_section_bytes<P: AsRef<Path>>(
    path: P,
    section_name: &str,
    require_bpf: bool,
) -> Result<Vec<u8>> {
    let buf = fs::read(path)?;
    let elf = Elf::parse(&buf)?;

    if require_bpf {
        const EM_BPF: u16 = 247;
        const EM_NONE: u16 = 0;
        if elf.header.e_machine != EM_BPF && elf.header.e_machine != EM_NONE {
            return Err(anyhow::anyhow!(
                "Not an eBPF ELF object (machine: {})",
                elf.header.e_machine
            ));
        }
    }

    let sh = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(section_name))
        .ok_or_else(|| anyhow::anyhow!("Section '{}' not found", section_name))?;

    let offset = sh.sh_offset as usize;
    let size = sh.sh_size as usize;

    if offset + size > buf.len() {
        return Err(anyhow::anyhow!("Section out of bounds"));
    }

    Ok(buf[offset..offset + size].to_vec())
}

pub fn load_bpf_insn_stream_section<P: AsRef<Path>>(
    path: P,
    section_name: &str,
) -> Result<Vec<u8>> {
    load_section_bytes(path, section_name, true)
}

pub fn load_raw_programs<P: AsRef<Path>>(path: P) -> Result<Vec<RawBpfProgram>> {
    let bytes = fs::read(path)?;
    let elf = Elf::parse(&bytes)?;
    let mut programs = Vec::new();

    for sym in elf.syms.iter() {
        if sym.st_type() == sym::STT_FUNC && sym.st_shndx < elf.section_headers.len() {
            let name = elf
                .strtab
                .get_at(sym.st_name)
                .unwrap_or("<unknown>")
                .to_string();
            let shdr = &elf.section_headers[sym.st_shndx];
            let file_offset = shdr.sh_offset as usize + sym.st_value as usize;
            let size = sym.st_size as usize;

            if file_offset + size <= bytes.len() && size > 0 {
                programs.push(RawBpfProgram {
                    name,
                    data: bytes[file_offset..file_offset + size].to_vec(),
                    section_idx: sym.st_shndx,
                    file_offset: file_offset as u64,
                });
            }
        }
    }

    // Fallback: If no STT_FUNC programs were found, but we have code sections,
    // treat each section as a single program.
    if programs.is_empty() {
        for (idx, sh) in elf.section_headers.iter().enumerate() {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if crate::testing::runner::is_code_section(name) {
                let file_offset = sh.sh_offset as usize;
                let size = sh.sh_size as usize;
                if file_offset + size <= bytes.len() && size > 0 {
                    programs.push(RawBpfProgram {
                        name: name.to_string(),
                        data: bytes[file_offset..file_offset + size].to_vec(),
                        section_idx: idx,
                        file_offset: file_offset as u64,
                    });
                }
            }
        }
    }

    Ok(programs)
}

/// Names of all STT_FUNC symbols whose ELF binding is global/weak AND
/// whose visibility is STV_HIDDEN or STV_INTERNAL. These are the subprogs
/// that libbpf demotes from BTF_FUNC_GLOBAL to BTF_FUNC_STATIC at load
/// (libbpf.c:3552), so the kernel verifies them inline with caller types
/// instead of the global-subprog "PTR_MAYBE_NULL on every pointer arg"
/// regime.
pub fn collect_hidden_subprog_names<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    use goblin::elf::sym::{STB_GLOBAL, STB_WEAK};
    const STV_INTERNAL: u8 = 1;
    const STV_HIDDEN: u8 = 2;

    let buf = fs::read(path)?;
    let elf = Elf::parse(&buf)?;
    let mut out = Vec::new();
    for s in elf.syms.iter() {
        if s.st_type() != sym::STT_FUNC {
            continue;
        }
        let bind = s.st_bind();
        if bind != STB_GLOBAL && bind != STB_WEAK {
            continue;
        }
        let vis = s.st_other & 0x3;
        if vis != STV_HIDDEN && vis != STV_INTERNAL {
            continue;
        }
        if let Some(name) = elf.strtab.get_at(s.st_name)
            && !name.is_empty() {
                out.push(name.to_string());
            }
    }
    Ok(out)
}

pub fn list_section_names<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let buf = fs::read(path)?;
    let elf = Elf::parse(&buf)?;
    Ok(elf
        .section_headers
        .iter()
        .filter_map(|sh| elf.shdr_strtab.get_at(sh.sh_name))
        .map(|s| s.to_string())
        .collect())
}

/// Get all STT_FUNC symbols (BPF functions) within a specific section.
/// Returns functions sorted by offset within the section.
pub fn get_functions_in_section<P: AsRef<Path>>(
    path: P,
    section_name: &str,
) -> Result<Vec<BpfFuncInfo>> {
    let buf = fs::read(path)?;
    let elf = Elf::parse(&buf)?;

    // Find the target section index
    let target_sec_idx = elf
        .section_headers
        .iter()
        .enumerate()
        .find(|(_, sh)| elf.shdr_strtab.get_at(sh.sh_name) == Some(section_name))
        .map(|(idx, _)| idx);

    let target_sec_idx = match target_sec_idx {
        Some(idx) => idx,
        None => return Ok(Vec::new()),
    };

    // Collect all STT_FUNC symbols in this section
    let mut functions: Vec<BpfFuncInfo> = elf
        .syms
        .iter()
        .filter(|sym| sym.st_type() == sym::STT_FUNC && sym.st_shndx == target_sec_idx)
        .map(|sym| {
            let name = elf
                .strtab
                .get_at(sym.st_name)
                .unwrap_or("<unknown>")
                .to_string();
            BpfFuncInfo {
                name,
                offset: sym.st_value as usize,
                size: sym.st_size as usize,
            }
        })
        .collect();

    // Sort by offset
    functions.sort_by_key(|f| f.offset);

    Ok(functions)
}

/// Load the raw bytes for a specific function within a section.
pub fn load_function_bytes<P: AsRef<Path>>(
    path: P,
    section_name: &str,
    func_name: &str,
) -> Result<Vec<u8>> {
    let buf = fs::read(&path)?;
    let elf = Elf::parse(&buf)?;

    // Find the target section
    let sh = elf
        .section_headers
        .iter()
        .enumerate()
        .find(|(_, sh)| elf.shdr_strtab.get_at(sh.sh_name) == Some(section_name));

    let (sec_idx, sh) = match sh {
        Some(s) => s,
        None => return Err(anyhow::anyhow!("Section '{}' not found", section_name)),
    };

    // Find the function symbol
    let func_sym = elf.syms.iter().find(|sym| {
        sym.st_type() == sym::STT_FUNC
            && sym.st_shndx == sec_idx
            && elf.strtab.get_at(sym.st_name) == Some(func_name)
    });

    let func_sym = match func_sym {
        Some(s) => s,
        None => {
            return Err(anyhow::anyhow!(
                "Function '{}' not found in section '{}'",
                func_name,
                section_name
            ));
        }
    };

    // Calculate file offset and extract bytes
    let file_offset = sh.sh_offset as usize + func_sym.st_value as usize;
    let size = func_sym.st_size as usize;

    if file_offset + size > buf.len() {
        return Err(anyhow::anyhow!("Function data out of bounds"));
    }

    Ok(buf[file_offset..file_offset + size].to_vec())
}
