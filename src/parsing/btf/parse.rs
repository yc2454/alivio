//! Top-level `parse_btf`: decodes the .BTF section into a populated
//! [`BtfContext`] (types, strings, decl_tags, kfunc registry).

use std::collections::{HashMap, HashSet};
use std::convert::TryInto;

use super::types::*;

/// Parses the .BTF section into a structured Context for analysis
pub fn parse_btf(bytes: &[u8]) -> Result<BtfContext, String> {
    let hdr = BtfHeader::parse(bytes)?;
    let type_start = hdr.type_start;
    let type_end = hdr.type_end;

    let strings = bytes[hdr.str_start..hdr.str_end].to_vec();
    let mut types = HashMap::new();
    let mut decl_tags = Vec::new();
    let mut cursor = type_start;
    let mut type_id = 1;

    while cursor < type_end {
        if cursor + 12 > type_end {
            break;
        }

        let name_off = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
        let info = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
        let size_or_type = u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap());
        cursor += 12;

        let kind = ((info >> 24) & 0x1f) as u8;
        let vlen = (info & 0xffff) as usize;
        let mut members = Vec::new();

        // Extract extra data based on Kind
        match kind {
            BTF_KIND_STRUCT | BTF_KIND_UNION => {
                for _ in 0..vlen {
                    if cursor + 12 > type_end {
                        break;
                    }
                    let m_name = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                    let m_type =
                        u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
                    let m_off =
                        u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap());
                    cursor += 12;
                    members.push(BtfMember {
                        name_off: m_name,
                        type_id: m_type,
                        offset: m_off,
                    });
                }
            }
            BTF_KIND_INT => {
                cursor += 4;
            }
            BTF_KIND_ARRAY => {
                // Trailing `struct btf_array { u32 elem_type; u32 index_type;
                // u32 nelems }`. ARRAY's header `size_or_type` slot is
                // unused per BTF spec, so we reuse `members[0]` to carry
                // `elem_type` (in type_id) and `nelems` (in offset). The
                // index_type is always an integer kind we don't need.
                if cursor + 12 <= type_end {
                    let elem_type =
                        u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                    let nelems =
                        u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap());
                    members.push(BtfMember {
                        name_off: 0,
                        type_id: elem_type,
                        offset: nelems,
                    });
                }
                cursor += 12;
            }
            BTF_KIND_VAR => {
                // VAR header carries the var's name (in `name_off`) and the
                // var's BTF type id (in `size_or_type`); the trailing 4 bytes
                // are linkage (BTF_VAR_STATIC / GLOBAL_ALLOCATED / EXTERN),
                // which we don't currently consume.
                cursor += 4;
            }
            BTF_KIND_DATASEC => {
                // Each entry is `struct btf_var_secinfo { u32 type; u32 offset;
                // u32 size }` — 12 bytes. Stash into `members` reusing the
                // existing slot: type_id = secinfo.type, offset = byte offset
                // within the section, name_off = secinfo.size (we repurpose
                // the unused name slot to carry the size — DATASEC entries
                // are unnamed in BTF, so name_off would otherwise be 0).
                // Callers use the helper `datasec_entries()` to read these
                // back without remembering the field reuse.
                for _ in 0..vlen {
                    if cursor + 12 > type_end {
                        break;
                    }
                    let s_type = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                    let s_off =
                        u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
                    let s_size =
                        u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap());
                    cursor += 12;
                    members.push(BtfMember {
                        name_off: s_size,
                        type_id: s_type,
                        offset: s_off,
                    });
                }
            }
            BTF_KIND_ENUM64 => {
                // Each value: { u32 name_off; u32 val_lo32; u32 val_hi32; }
                // We pack into BtfMember by repurposing fields:
                //   name_off = enum-value name string offset
                //   type_id  = val_hi32 (upper 32 bits)
                //   offset   = val_lo32 (lower 32 bits)
                // BtfType.kind() being ENUM64 disambiguates the layout.
                // Used by CO-RE EnumvalExists/EnumvalValue relo resolution
                // — without this, enum values can't be looked up by name.
                for _ in 0..vlen {
                    if cursor + 12 > type_end {
                        break;
                    }
                    let v_name = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                    let v_lo = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
                    let v_hi = u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap());
                    cursor += 12;
                    members.push(BtfMember {
                        name_off: v_name,
                        type_id: v_hi,
                        offset: v_lo,
                    });
                }
            }
            BTF_KIND_ENUM => {
                // Each value: { u32 name_off; i32 val; }
                // Pack into BtfMember: name_off = value-name string offset,
                // offset = value as u32 (signed → u32 reinterpret).
                // BtfType.kind() being ENUM disambiguates the layout.
                for _ in 0..vlen {
                    if cursor + 8 > type_end {
                        break;
                    }
                    let v_name = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                    let v_val = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
                    cursor += 8;
                    members.push(BtfMember {
                        name_off: v_name,
                        type_id: 0,
                        offset: v_val,
                    });
                }
            }
            BTF_KIND_FUNC_PROTO => {
                // Each param is `struct btf_param { u32 name_off; u32 type; }`.
                // Return type is in `size_or_type` (already captured above).
                // We reuse `members` to carry the params: `BtfMember.name_off` →
                // param name, `BtfMember.type_id` → param type, `offset` is unused
                // for FUNC_PROTO (set to 0). This keeps BtfType uniform without
                // adding a parallel `params` field.
                for _ in 0..vlen {
                    if cursor + 8 > type_end {
                        break;
                    }
                    let p_name = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                    let p_type =
                        u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
                    cursor += 8;
                    members.push(BtfMember {
                        name_off: p_name,
                        type_id: p_type,
                        offset: 0,
                    });
                }
            }
            BTF_KIND_DECL_TAG => {
                if cursor + 4 <= type_end {
                    let component_idx = i32::from_le_bytes(
                        bytes[cursor..cursor + 4].try_into().unwrap(),
                    );
                    // Defer resolving the tag name string until after the
                    // full strings blob is installed on BtfContext.
                    decl_tags.push(DeclTag {
                        name: String::new(), // filled in below
                        target_type_id: size_or_type,
                        component_idx,
                    });
                    // Stash the name_off on the last decl_tag via a sentinel:
                    // we use a fresh field on the parsed type (below) to
                    // carry the string offset. Simpler: look up strings now.
                    let last = decl_tags.last_mut().unwrap();
                    let start = name_off as usize;
                    if start < strings.len()
                        && let Some(end) =
                            strings[start..].iter().position(|&b| b == 0).map(|e| e + start)
                            && let Ok(s) = std::str::from_utf8(&strings[start..end]) {
                                last.name = s.to_string();
                            }
                    cursor += 4;
                }
            }
            _ => {}
        }

        types.insert(
            type_id,
            BtfType {
                id: type_id,
                name_off,
                info,
                size_or_type,
                members,
            },
        );

        type_id += 1;
    }

    // Build the kfunc registry: FUNC types targeted by a DECL_TAG whose name
    // is "kfunc" or "bpf_kfunc" get indexed by the FUNC's own name.
    let mut kfuncs: HashMap<String, u32> = HashMap::new();
    for tag in &decl_tags {
        if tag.name != "kfunc" && tag.name != "bpf_kfunc" {
            continue;
        }
        let Some(func_ty) = types.get(&tag.target_type_id) else {
            continue;
        };
        if func_ty.kind() != BTF_KIND_FUNC {
            continue;
        }
        let start = func_ty.name_off as usize;
        if start >= strings.len() {
            continue;
        }
        let Some(end) = strings[start..].iter().position(|&b| b == 0).map(|e| e + start) else {
            continue;
        };
        let Ok(name) = std::str::from_utf8(&strings[start..end]) else {
            continue;
        };
        kfuncs.insert(name.to_string(), tag.target_type_id);
    }

    Ok(BtfContext {
        types,
        strings,
        decl_tags,
        kfuncs,
        hidden_subprogs: HashSet::new(),
        special_fields_cache: Default::default(),
        btf_ext: None,
    })
}
