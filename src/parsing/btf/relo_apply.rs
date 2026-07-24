//! CO-RE relocation application. Mirrors libbpf's
//! `bpf_core_apply_relo_insn` / `bpf_core_patch_insn`
//! (tools/lib/bpf/relo_core.c). For each `CoreRelo` of a supported
//! kind, resolve the local↔target match against a target BTF and patch
//! the corresponding instruction's `imm` field.
//!
//! Coverage:
//!   * `EnumvalExists` — set imm to 1 iff the target BTF has an enum
//!     (matching the local enum's name if named) with a value whose
//!     name matches the local enum's `access_idx`th value name.
//!   * `FieldExists` — set imm to 1 iff the target BTF has a struct/
//!     union with a field whose name matches the path-end local field.
//!     Currently handles single-level access only (e.g. "0:N"); nested
//!     fields are not supported.
//!
//! Unsupported kinds (FieldByteOffset, FieldByteSize, TypeSize, …) are
//! counted but not patched.

use crate::parsing::bpf_insn::RawBpfInsn;
use crate::parsing::btf::ext::{CoreRelo, CoreReloKind};
use crate::parsing::btf::types::{BTF_KIND_ENUM, BTF_KIND_STRUCT, BTF_KIND_UNION, BtfContext};

// ENUM64 is BTF kind 19; mirror locally since types.rs doesn't export it as a const.
const BTF_KIND_ENUM64: u8 = 19;

#[derive(Default, Debug, Clone, Copy)]
pub struct ReloStats {
    pub enum_exists_applied: u32,
    pub enum_exists_skipped: u32,
    pub field_exists_applied: u32,
    pub field_exists_skipped: u32,
    pub unsupported_kind: u32,
    pub patch_failed: u32,
    /// Of the "applied" patches, how many were no-ops (resolved value
    /// equaled the placeholder clang already inlined — clang emits the
    /// "guess the feature exists" default imm=1 and target BTF agrees).
    pub no_op: u32,
}

/// Read a null-terminated UTF-8 string from a BTF strings table at the
/// given byte offset. Returns "" on OOB or invalid UTF-8.
fn cstr(strs: &[u8], off: u32) -> &str {
    let s = off as usize;
    if s >= strs.len() {
        return "";
    }
    let end = strs[s..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| s + p)
        .unwrap_or(strs.len());
    std::str::from_utf8(&strs[s..end]).unwrap_or("")
}

/// Apply CO-RE relocations to `raw_insns`. `section_off_to_insn_idx`
/// maps a relo's `insn_off` (byte offset within its containing section)
/// to an index in `raw_insns`. For a single-section load, this is
/// typically `|off| Some(off as usize / 8)`.
pub fn apply_core_relos(
    program_btf: &BtfContext,
    target_btf: &BtfContext,
    relos: &[CoreRelo],
    raw_insns: &mut [RawBpfInsn],
    section_off_to_insn_idx: impl Fn(u32) -> Option<usize>,
) -> ReloStats {
    let mut stats = ReloStats::default();
    for relo in relos {
        let insn_idx = match section_off_to_insn_idx(relo.insn_off) {
            Some(i) if i < raw_insns.len() => i,
            _ => {
                match relo.kind {
                    CoreReloKind::EnumvalExists => stats.enum_exists_skipped += 1,
                    CoreReloKind::FieldExists => stats.field_exists_skipped += 1,
                    _ => stats.unsupported_kind += 1,
                }
                continue;
            }
        };
        let new_val: Option<u64> = match relo.kind {
            CoreReloKind::EnumvalExists => Some(
                if check_enum_value_exists(program_btf, target_btf, relo) {
                    1
                } else {
                    0
                },
            ),
            CoreReloKind::FieldExists => Some(
                if check_field_exists(program_btf, target_btf, relo) {
                    1
                } else {
                    0
                },
            ),
            _ => {
                stats.unsupported_kind += 1;
                None
            }
        };
        let Some(val) = new_val else { continue };
        let was_imm = raw_insns[insn_idx].imm;
        let was_no_op = was_imm as u64 == val;
        if patch_insn(raw_insns, insn_idx, val) {
            if was_no_op {
                stats.no_op += 1;
            }
            match relo.kind {
                CoreReloKind::EnumvalExists => stats.enum_exists_applied += 1,
                CoreReloKind::FieldExists => stats.field_exists_applied += 1,
                _ => {}
            }
        } else {
            stats.patch_failed += 1;
        }
    }
    stats
}

/// Resolve `EnumvalExists` for one relocation.
fn check_enum_value_exists(
    program_btf: &BtfContext,
    target_btf: &BtfContext,
    relo: &CoreRelo,
) -> bool {
    let Some(local_ty) = program_btf.types.get(&relo.type_id) else {
        return false;
    };
    let lkind = local_ty.kind();
    if lkind != BTF_KIND_ENUM && lkind != BTF_KIND_ENUM64 {
        return false;
    }
    // Access string for EnumvalExists is a single decimal: the value index.
    let access_str = cstr(&program_btf.strings, relo.access_str_off);
    let value_idx: usize = match access_str.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    if value_idx >= local_ty.members.len() {
        return false;
    }
    let value_name = cstr(&program_btf.strings, local_ty.members[value_idx].name_off);
    if value_name.is_empty() {
        return false;
    }
    let local_enum_name = cstr(&program_btf.strings, local_ty.name_off);

    // Search target BTF for an enum (matching local enum's name if it has one)
    // whose values include `value_name`. Mirrors libbpf's
    // `bpf_core_find_cands` + ENUMVAL spec matching.
    for target_ty in target_btf.types.values() {
        let tkind = target_ty.kind();
        if tkind != BTF_KIND_ENUM && tkind != BTF_KIND_ENUM64 {
            continue;
        }
        if !local_enum_name.is_empty() {
            let tname = cstr(&target_btf.strings, target_ty.name_off);
            if tname != local_enum_name {
                continue;
            }
        }
        for m in &target_ty.members {
            let tname = cstr(&target_btf.strings, m.name_off);
            if tname == value_name {
                return true;
            }
        }
    }
    false
}

/// Resolve `FieldExists` for one relocation. Single-level access only
/// (path = [0, N]); nested fields are not supported.
fn check_field_exists(program_btf: &BtfContext, target_btf: &BtfContext, relo: &CoreRelo) -> bool {
    let Some(local_ty) = program_btf.types.get(&relo.type_id) else {
        return false;
    };
    let lkind = local_ty.kind();
    if lkind != BTF_KIND_STRUCT && lkind != BTF_KIND_UNION {
        return false;
    }
    let access_str = cstr(&program_btf.strings, relo.access_str_off);
    let path: Vec<usize> = access_str
        .split(':')
        .filter_map(|s| s.parse().ok())
        .collect();
    // Need path of form [0, N] (root + one field index).
    if path.len() != 2 || path[0] != 0 {
        return false;
    }
    let field_idx = path[1];
    if field_idx >= local_ty.members.len() {
        return false;
    }
    let field_name = cstr(&program_btf.strings, local_ty.members[field_idx].name_off);
    if field_name.is_empty() {
        return false;
    }
    let local_struct_name = cstr(&program_btf.strings, local_ty.name_off);

    // Search target BTF for a struct/union (matching local name if named)
    // whose members include `field_name`.
    for target_ty in target_btf.types.values() {
        let tkind = target_ty.kind();
        if tkind != BTF_KIND_STRUCT && tkind != BTF_KIND_UNION {
            continue;
        }
        if !local_struct_name.is_empty() {
            let tname = cstr(&target_btf.strings, target_ty.name_off);
            if tname != local_struct_name {
                continue;
            }
        }
        for m in &target_ty.members {
            let tname = cstr(&target_btf.strings, m.name_off);
            if tname == field_name {
                return true;
            }
        }
    }
    false
}

/// Patch the instruction at `idx`. Mirrors libbpf `bpf_core_patch_insn`
/// for ALU/ALU64 and LDIMM64 classes — the only classes that carry
/// EnumvalExists/FieldExists results (which always become a 0/1 imm).
/// Returns true on success.
fn patch_insn(raw_insns: &mut [RawBpfInsn], idx: usize, val: u64) -> bool {
    if idx >= raw_insns.len() {
        return false;
    }
    let class = raw_insns[idx].code & 0x07;
    // BPF classes: LD=0x00, LDX=0x01, ST=0x02, STX=0x03, ALU=0x04, JMP=0x05, JMP32=0x06, ALU64=0x07.
    match class {
        // ALU / ALU64: imm holds the relocated value.
        0x04 | 0x07 => {
            raw_insns[idx].imm = val as i64 as i32;
            true
        }
        // LD: only ldimm64 is patched (LD_IMM64 spans 2 insn slots; imm32 split low/high).
        0x00 => {
            if idx + 1 >= raw_insns.len() {
                return false;
            }
            raw_insns[idx].imm = (val as u32) as i32;
            raw_insns[idx + 1].imm = ((val >> 32) as u32) as i32;
            true
        }
        // LDX/ST/STX: off carries the relocated field byte-offset. Not used for
        // EnumvalExists/FieldExists (those land on ALU/LDIMM64), so unsupported here.
        _ => false,
    }
}
