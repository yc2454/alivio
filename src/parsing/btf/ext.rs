//! `.BTF.ext` parser — CO-RE relocation records.
//!
//! `.BTF.ext` is a sibling section of `.BTF` that carries:
//!   - `func_info` — per-function PC ↔ BTF FUNC mappings (for stack traces)
//!   - `line_info` — per-PC source-line metadata (for stack traces)
//!   - `core_relo` — CO-RE relocation records (for `__attribute__((preserve_access_index))`
//!                  and the `bpf_core_*` macro family)
//!
//! Today this module only parses the `core_relo` section — `func_info` /
//! `line_info` are skipped (we don't emit stack traces). The records are
//! surfaced via [`BtfExt`] so future work can apply CO-RE field-offset /
//! field-size / type-id rewrites at insn time. Resolution requires either
//! a vmlinux BTF or a runtime-supplied target BTF; neither is wired today,
//! so the parser exists as foundation rather than a closure source.
//!
//! Format reference: kernel `tools/lib/bpf/btf.c` `btf_ext_parse_hdr` and
//! `tools/lib/bpf/relo_core.h` `bpf_core_relo`.

use std::convert::TryInto;

const BTF_MAGIC_LE: u16 = 0xEB9F;

/// CO-RE relocation kind (mirrors kernel `enum bpf_core_relo_kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Foundation: future passes will dispatch on kind.
pub enum CoreReloKind {
    FieldByteOffset = 0,
    FieldByteSize = 1,
    FieldExists = 2,
    FieldSigned = 3,
    FieldLshiftU64 = 4,
    FieldRshiftU64 = 5,
    TypeIdLocal = 6,
    TypeIdTarget = 7,
    TypeExists = 8,
    TypeSize = 9,
    EnumvalExists = 10,
    EnumvalValue = 11,
    TypeMatches = 12,
}

impl CoreReloKind {
    fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::FieldByteOffset,
            1 => Self::FieldByteSize,
            2 => Self::FieldExists,
            3 => Self::FieldSigned,
            4 => Self::FieldLshiftU64,
            5 => Self::FieldRshiftU64,
            6 => Self::TypeIdLocal,
            7 => Self::TypeIdTarget,
            8 => Self::TypeExists,
            9 => Self::TypeSize,
            10 => Self::EnumvalExists,
            11 => Self::EnumvalValue,
            12 => Self::TypeMatches,
            _ => return None,
        })
    }
}

/// One CO-RE relocation record. `insn_off` is bytes from the start of the
/// owning section's bytecode (divide by 8 for the instruction index).
#[derive(Debug, Clone)]
#[allow(dead_code)] // Foundation: fields read by future resolver.
pub struct CoreRelo {
    /// Byte offset of the target instruction within the owning section.
    pub insn_off: u32,
    /// Local BTF type id this relo describes.
    pub type_id: u32,
    /// Resolved access spec string (e.g. `"0:1:2"` — array-index then
    /// member indices). Pre-resolved here for caller convenience; the raw
    /// `access_str_off` is also available via [`CoreRelo::access_str_off`].
    pub access_spec: String,
    /// Raw `.BTF` strings offset for the access spec.
    pub access_str_off: u32,
    pub kind: CoreReloKind,
}

/// Parsed `.BTF.ext` content. Maps section name to the list of CO-RE
/// relos that target that section's bytecode.
#[derive(Debug, Default, Clone)]
#[allow(dead_code)] // Foundation: consumed by future resolver.
pub struct BtfExt {
    /// Section name (e.g. `"raw_tp/sys_exit"`) → CO-RE relos for that
    /// section, in record order.
    pub core_relos_by_section: Vec<(String, Vec<CoreRelo>)>,
}

/// Parse a `.BTF.ext` blob. `btf_strings` is the strings blob from the
/// sibling `.BTF` section (record offsets index into it).
pub fn parse_btf_ext(bytes: &[u8], btf_strings: &[u8]) -> Result<BtfExt, String> {
    if bytes.len() < 24 {
        return Err("BTF.ext too short".into());
    }
    // Header layout (little-endian):
    //   u16 magic; u8 version; u8 flags; u32 hdr_len;
    //   u32 func_info_off, func_info_len;
    //   u32 line_info_off, line_info_len;
    //   [u32 core_relo_off, core_relo_len;]   // optional, hdr_len > 32
    let magic = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
    if magic != BTF_MAGIC_LE {
        return Err(format!("BTF.ext bad magic: 0x{magic:04x}"));
    }
    let version = bytes[2];
    if version != 1 {
        return Err(format!("BTF.ext unsupported version: {version}"));
    }
    let hdr_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    if hdr_len < 24 || hdr_len > bytes.len() {
        return Err(format!("BTF.ext bad hdr_len: {hdr_len}"));
    }

    // Offsets are bytes from the END of the header.
    let payload_base = hdr_len;

    // core_relo block is optional — present only when hdr_len >= 32.
    let (core_off, core_len) = if hdr_len >= 32 {
        let off = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(bytes[28..32].try_into().unwrap()) as usize;
        (off, len)
    } else {
        return Ok(BtfExt::default());
    };

    let core_start = payload_base + core_off;
    let core_end = core_start + core_len;
    if core_len == 0 {
        return Ok(BtfExt::default());
    }
    if core_end > bytes.len() {
        return Err("BTF.ext core_relo out of bounds".into());
    }

    let core_bytes = &bytes[core_start..core_end];
    parse_core_relos(core_bytes, btf_strings)
}

/// Parse the core_relo info area. Layout:
///   u32 record_size;                       // bytes per CO-RE relo record (16)
///   repeated:
///     u32 sec_name_off;                    // .BTF strings offset for the SEC name
///     u32 num_records;
///     [record_size bytes] * num_records    // bpf_core_relo records
fn parse_core_relos(bytes: &[u8], btf_strings: &[u8]) -> Result<BtfExt, String> {
    if bytes.len() < 4 {
        return Err("core_relo area too short".into());
    }
    let record_size = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if record_size != 16 {
        // Older / future kernels may extend the record; we only know the
        // 16-byte v1 layout. Surface as a soft error so callers can keep
        // going without CO-RE resolution.
        return Err(format!("core_relo unsupported record_size: {record_size}"));
    }

    let mut cursor = 4;
    let mut sections: Vec<(String, Vec<CoreRelo>)> = Vec::new();

    while cursor < bytes.len() {
        if cursor + 8 > bytes.len() {
            return Err("core_relo per-section header truncated".into());
        }
        let sec_name_off =
            u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        let num_records =
            u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;

        let records_byte_len = num_records.checked_mul(record_size).ok_or_else(|| {
            "core_relo num_records * record_size overflow".to_string()
        })?;
        if cursor + records_byte_len > bytes.len() {
            return Err("core_relo records truncated".into());
        }

        let sec_name = read_btf_string(btf_strings, sec_name_off);

        let mut relos = Vec::with_capacity(num_records);
        for i in 0..num_records {
            let r_start = cursor + i * record_size;
            let insn_off =
                u32::from_le_bytes(bytes[r_start..r_start + 4].try_into().unwrap());
            let type_id =
                u32::from_le_bytes(bytes[r_start + 4..r_start + 8].try_into().unwrap());
            let access_str_off =
                u32::from_le_bytes(bytes[r_start + 8..r_start + 12].try_into().unwrap());
            let kind_raw =
                u32::from_le_bytes(bytes[r_start + 12..r_start + 16].try_into().unwrap());
            let Some(kind) = CoreReloKind::from_u32(kind_raw) else {
                // Unknown kind — skip individually (future kernels may add
                // kinds we don't model). Pre-existing valid records should
                // still surface.
                continue;
            };
            let access_spec = read_btf_string(btf_strings, access_str_off as usize);
            relos.push(CoreRelo {
                insn_off,
                type_id,
                access_spec,
                access_str_off,
                kind,
            });
        }
        cursor += records_byte_len;

        sections.push((sec_name, relos));
    }

    Ok(BtfExt {
        core_relos_by_section: sections,
    })
}

fn read_btf_string(strings: &[u8], off: usize) -> String {
    if off >= strings.len() {
        return String::new();
    }
    let end = strings[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(strings.len());
    std::str::from_utf8(&strings[off..end])
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_blob(record_size: u32, sections: &[(u32, &[(u32, u32, u32, u32)])]) -> Vec<u8> {
        // Minimal .BTF.ext blob: 24-byte header + empty func_info + empty
        // line_info + a core_relo area with the given sections.
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&BTF_MAGIC_LE.to_le_bytes()); // magic
        hdr.push(1); // version
        hdr.push(0); // flags
        hdr.extend_from_slice(&32u32.to_le_bytes()); // hdr_len = 32 (with core_relo)
        hdr.extend_from_slice(&0u32.to_le_bytes()); // func_info_off
        hdr.extend_from_slice(&0u32.to_le_bytes()); // func_info_len
        hdr.extend_from_slice(&0u32.to_le_bytes()); // line_info_off
        hdr.extend_from_slice(&0u32.to_le_bytes()); // line_info_len
        hdr.extend_from_slice(&0u32.to_le_bytes()); // core_relo_off (right after header)
        let mut core_payload = Vec::new();
        core_payload.extend_from_slice(&record_size.to_le_bytes());
        for (sec_name_off, records) in sections {
            core_payload.extend_from_slice(&sec_name_off.to_le_bytes());
            core_payload.extend_from_slice(&(records.len() as u32).to_le_bytes());
            for (insn_off, type_id, access_str_off, kind) in *records {
                core_payload.extend_from_slice(&insn_off.to_le_bytes());
                core_payload.extend_from_slice(&type_id.to_le_bytes());
                core_payload.extend_from_slice(&access_str_off.to_le_bytes());
                core_payload.extend_from_slice(&kind.to_le_bytes());
            }
        }
        hdr.extend_from_slice(&(core_payload.len() as u32).to_le_bytes()); // core_relo_len
        hdr.extend_from_slice(&core_payload);
        hdr
    }

    #[test]
    fn parses_one_section_one_relo() {
        // Strings: [0]=NUL, [1..]="raw_tp/x\0", [...]="0:1\0"
        let mut strings = vec![0u8];
        let sec_name_off = strings.len() as u32;
        strings.extend_from_slice(b"raw_tp/x\0");
        let acc_off = strings.len() as u32;
        strings.extend_from_slice(b"0:1\0");

        let blob = build_blob(16, &[(sec_name_off, &[(64, 7, acc_off, 0)])]);
        let ext = parse_btf_ext(&blob, &strings).expect("parse");
        assert_eq!(ext.core_relos_by_section.len(), 1);
        let (name, relos) = &ext.core_relos_by_section[0];
        assert_eq!(name, "raw_tp/x");
        assert_eq!(relos.len(), 1);
        assert_eq!(relos[0].insn_off, 64);
        assert_eq!(relos[0].type_id, 7);
        assert_eq!(relos[0].access_spec, "0:1");
        assert_eq!(relos[0].kind, CoreReloKind::FieldByteOffset);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut blob = build_blob(16, &[]);
        blob[0] = 0; // corrupt magic
        assert!(parse_btf_ext(&blob, &[]).is_err());
    }

    #[test]
    fn skips_unknown_kind() {
        let mut strings = vec![0u8];
        let sec_name_off = strings.len() as u32;
        strings.extend_from_slice(b"sec\0");
        let acc_off = strings.len() as u32;
        strings.extend_from_slice(b"0\0");
        // kind=99 (unknown) — should be silently dropped, not error.
        let blob = build_blob(16, &[(sec_name_off, &[(0, 1, acc_off, 99)])]);
        let ext = parse_btf_ext(&blob, &strings).expect("parse");
        assert_eq!(ext.core_relos_by_section.len(), 1);
        assert_eq!(ext.core_relos_by_section[0].1.len(), 0);
    }
}
