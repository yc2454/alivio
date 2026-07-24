//! BTF-driven map-def discovery for libbpf-style `.maps`-section maps.
//!
//! Walks the parsed [`BtfContext`] looking for `BTF_KIND_VAR`s whose
//! target struct has the libbpf `__type(key, …)` / `__type(value, …)` /
//! `__uint(type, …)` / `__uint(max_entries, …)` member shape, and emits
//! one [`BpfMapDef`] per recognized map. Kptr-tagged value fields are
//! lifted via [`BtfContext::extract_value_kptr_fields`].

use log::info;

use crate::parsing::elf::{BpfMapDef, KptrField};

use super::parse::parse_btf;
use super::types::*;

/// `__uint(name, val)` lowers to `PTR -> ARRAY[val]` in BTF: the value
/// is encoded as the array element count. Returns the count if `type_id`
/// matches that shape (after peeling modifiers), else None.
fn extract_btf_uint(ctx: &BtfContext, type_id: u32) -> Option<u32> {
    let id = ctx.peel_modifiers(type_id);
    let ptr = ctx.types.get(&id)?;
    if ptr.kind() != BTF_KIND_PTR {
        return None;
    }
    let arr_id = ctx.peel_modifiers(ptr.size_or_type);
    let arr = ctx.types.get(&arr_id)?;
    if arr.kind() != BTF_KIND_ARRAY {
        return None;
    }
    // ARRAY's parsed member[0] carries (elem_type=type_id, nelems=offset).
    Some(arr.members.first()?.offset)
}

/// Extract the inner-map struct BTF type id from a libbpf
/// `__array(values, struct inner_t)` member. The macro expands to
/// `typeof(struct inner_t) *values[]` so the encoding is
/// `ARRAY[PTR -> struct inner_t]`. Returns the peeled
/// `struct inner_t`'s type id. Used to resolve `inner_map_idx` for
/// ARRAY_OF_MAPS / HASH_OF_MAPS outer maps so subsequent
/// `bpf_map_lookup_elem` chains carry the inner's value-type BTF
/// (drives map_in_map_btf, mmap_inner_array, timer_mim — all blocked
/// because the outer's inner BTF was unresolved).
fn extract_btf_array_inner_struct(ctx: &BtfContext, type_id: u32) -> Option<u32> {
    let arr_id = ctx.peel_modifiers(type_id);
    let arr = ctx.types.get(&arr_id)?;
    if arr.kind() != BTF_KIND_ARRAY {
        return None;
    }
    // ARRAY's parsed member[0].type_id is the element type. Element
    // is PTR -> struct inner_t.
    let elem_id = ctx.peel_modifiers(arr.members.first()?.type_id);
    let elem = ctx.types.get(&elem_id)?;
    if elem.kind() != BTF_KIND_PTR {
        return None;
    }
    Some(ctx.peel_modifiers(elem.size_or_type))
}

/// Parsed libbpf-style map members of a single BTF struct. Shared by
/// the top-level `BTF_KIND_VAR` walk and the inline inner-map-template
/// resolution (an `__array(values, struct {…})` element whose struct is
/// itself a full map definition, not a reference to a sibling map VAR).
struct ParsedMapStruct {
    is_map: bool,
    value_size: u32,
    key_size: u32,
    max_entries: u32,
    map_type: u32,
    map_flags: u32,
    btf_val_type_id: Option<u32>,
    /// For ARRAY_OF_MAPS / HASH_OF_MAPS: the `struct inner_t` id from
    /// `__array(values, struct inner_t)`.
    inner_struct_id: Option<u32>,
}

/// Parse a libbpf map-definition struct's members (`type`, `key`,
/// `value`, `value_size`, `key_size`, `max_entries`, `map_flags`,
/// `values`). Pure over `def_t`'s members; no allocation beyond the
/// returned ids.
fn parse_map_struct_members(ctx: &BtfContext, def_t: &BtfType) -> ParsedMapStruct {
    let mut is_map = false;
    let mut value_size = 0;
    let mut key_size = 0;
    let mut max_entries = 0;
    let mut map_type = 0u32;
    let mut map_flags = 0u32;
    let mut btf_val_type_id: Option<u32> = None;
    let mut inner_struct_id: Option<u32> = None;

    for member in &def_t.members {
        let m_name = ctx.read_string(member.name_off).unwrap_or("");
        if m_name == "key" || m_name == "value" || m_name == "values" {
            is_map = true;
            // libbpf encodes `__type(value, T)` as a pointer to T;
            // peel one PTR layer to get the value type itself.
            let mut actual_type_id = member.type_id;
            if let Some(field_t) = ctx.types.get(&actual_type_id)
                && field_t.kind() == BTF_KIND_PTR
            {
                actual_type_id = field_t.size_or_type;
            }
            let size = ctx.type_size_bytes(actual_type_id);
            if m_name == "value" {
                value_size = size;
                btf_val_type_id = Some(actual_type_id);
            } else if m_name == "values" {
                // For map-in-map (ARRAY_OF_MAPS/HASH_OF_MAPS), the "values"
                // field is `__array(values, struct inner_t)` — the value
                // is a pointer to an inner map of type `struct inner_t`.
                // Record `inner_t`'s id so the post-pass can resolve
                // `inner_map_idx` to whichever sibling map_def declared
                // its variable as `struct inner_t`, or — when the inner
                // is an inline anonymous map template (no sibling VAR) —
                // parse that struct directly. Without this,
                // `bpf_map_lookup_elem` on the outer keeps the outer's
                // map_idx and the inner-lookup chain loses the inner
                // value's size/BTF (indexed inner-value loads get
                // bounded by the 4-byte of-maps fd slot; Timer/SpinLock
                // validators reject with "map has no value-type BTF").
                value_size = 4;
                inner_struct_id = extract_btf_array_inner_struct(ctx, member.type_id);
            } else {
                key_size = size;
            }
        } else if m_name == "type" {
            if let Some(val) = extract_btf_uint(ctx, member.type_id) {
                map_type = val;
                // Valueless map kinds (ARENA, RINGBUF, USER_RINGBUF,
                // CGRP_STORAGE …) declare only `type` + `max_entries`
                // and never appear with a `key`/`value` member, so
                // without this the libbpf-style `.maps` section
                // parser sees an all-zero record and the BTF
                // merger drops the map silently.
                is_map = true;
            }
        } else if m_name == "max_entries" {
            if let Some(val) = extract_btf_uint(ctx, member.type_id) {
                max_entries = val;
            }
        } else if m_name == "value_size" {
            // Alternative way to specify value size using __uint.
            is_map = true;
            if let Some(val) = extract_btf_uint(ctx, member.type_id) {
                value_size = val;
            }
        } else if m_name == "key_size" {
            is_map = true;
            if let Some(val) = extract_btf_uint(ctx, member.type_id) {
                key_size = val;
            }
        } else if m_name == "map_flags" {
            // `__uint(map_flags, BPF_F_RDONLY_PROG)` — encoded as
            // pointer-to-array with nelems = flag value, same as
            // type/max_entries above.
            if let Some(val) = extract_btf_uint(ctx, member.type_id) {
                map_flags = val;
            }
        }
    }

    ParsedMapStruct {
        is_map,
        value_size,
        key_size,
        max_entries,
        map_type,
        map_flags,
        btf_val_type_id,
        inner_struct_id,
    }
}

/// Build a [`BpfMapDef`] from a parsed map struct, lifting kptr value
/// fields. Returns `None` for non-maps / valueless structs that aren't a
/// recognized valueless map kind.
fn map_def_from_parsed(
    ctx: &BtfContext,
    name: String,
    p: &ParsedMapStruct,
) -> Option<BpfMapDef> {
    // Valueless maps (ARENA / RINGBUF / USER_RINGBUF / CGRP_STORAGE)
    // legitimately have value_size == 0; for everything else require
    // value_size > 0 to avoid picking up unrelated BTF structs that
    // happen to have a `type` member.
    let is_valueless_map = matches!(p.map_type, 27 | 31 | 32 | 33);
    if !(p.is_map && (p.value_size > 0 || is_valueless_map)) {
        return None;
    }
    let kptr_fields: Vec<KptrField> = p
        .btf_val_type_id
        .map(|id| ctx.extract_value_kptr_fields(id))
        .unwrap_or_default();
    if !kptr_fields.is_empty() {
        info!(target: "app", "[BTF] Map '{}' has {} kptr field(s): {:?}",
            name, kptr_fields.len(), kptr_fields);
    }
    Some(BpfMapDef {
        name,
        type_: p.map_type,
        key_size: p.key_size,
        value_size: p.value_size,
        max_entries: p.max_entries,
        map_flags: p.map_flags,
        btf_val_type_id: p.btf_val_type_id,
        initial_data: None,
        inner_map_idx: None,
        kptr_fields,
        extern_var_offsets: Vec::new(),
    })
}

pub fn parse_btf_map_defs(bytes: &[u8]) -> Result<Vec<BpfMapDef>, String> {
    let ctx = parse_btf(bytes)?;
    let mut map_defs = Vec::new();
    // (map_def_index, declaring_struct_id) — used to resolve outer
    // map-of-maps `inner_map_idx` after the first pass: the outer
    // records its `__array(values, struct T)` inner struct id and we
    // match against the inner map's declaring struct (its BTF VAR's
    // `size_or_type`). Mirrors libbpf's bpf_map__inner_map resolution.
    let mut def_struct_ids: Vec<u32> = Vec::new();
    // Per-map outer-side inner struct id (Some only for ARRAY_OF_MAPS /
    // HASH_OF_MAPS that declared `__array(values, struct T)`).
    let mut pending_inner_struct: Vec<Option<u32>> = Vec::new();
    info!(target: "app", "Scanning {} BTF types for Maps...", ctx.types.len());

    for ty in ctx.types.values() {
        if ty.kind() != BTF_KIND_VAR {
            continue;
        }
        let name = ctx.read_string(ty.name_off).unwrap_or("").to_string();
        // Peel typedef wrappers around the var's declared type to reach
        // the underlying struct definition.
        let def_id = ctx.peel_modifiers(ty.size_or_type);
        let Some(def_t) = ctx.types.get(&def_id) else {
            continue;
        };
        if def_t.kind() != BTF_KIND_STRUCT {
            continue;
        }

        let p = parse_map_struct_members(&ctx, def_t);
        let inner_struct_id = p.inner_struct_id;
        if let Some(md) = map_def_from_parsed(&ctx, name, &p) {
            info!(target: "app", "[BTF] Found Map: '{}' (Type: {}, KeySize: {}, ValSize: {}, MaxEntries: {}, TypeID: {:?})",
                md.name, md.type_, md.key_size, md.value_size, md.max_entries, md.btf_val_type_id);
            map_defs.push(md);
            def_struct_ids.push(def_id);
            pending_inner_struct.push(inner_struct_id);
        }
    }

    // Post-pass: resolve ARRAY_OF_MAPS / HASH_OF_MAPS outer maps to
    // their inner map_idx. The outer's `__array(values, struct T)`
    // recorded `T`'s type id. Two libbpf-supported shapes:
    //   (a) `T` is a sibling top-level map VAR's declaring struct —
    //       point at that map_def.
    //   (b) `T` is an inline anonymous struct that is itself a full
    //       map definition (`__array(values, struct { __uint(type,…);
    //       __uint(value_size,…); … })`) — there is no sibling VAR, so
    //       parse `T` directly and synthesize an inner map_def. Without
    //       this the outer keeps value_size 4 (the of-maps fd slot) and
    //       indexed inner-value loads `value[hash % N]` look OOB.
    // Mirrors libbpf `bpf_object__init_user_btf_map` inner-map setup.
    //
    // Storing as the index *into this `map_defs` vector* is OK as long
    // as the consumer treats this vector as the canonical map list. The
    // ELF loader's merge path (`load_maps` in elf/map.rs) re-resolves
    // by name to translate this index into the live `maps` vector
    // (which may have a different ordering); it also appends synthesized
    // inline inners (no ELF symbol) to the live vector.
    let mut synth_inner_by_struct: std::collections::HashMap<u32, usize> =
        std::collections::HashMap::new();
    for i in 0..pending_inner_struct.len() {
        let Some(inner_id) = pending_inner_struct[i] else {
            continue;
        };
        let target = map_defs[i].type_;
        if target != crate::common::constants::BPF_MAP_TYPE_ARRAY_OF_MAPS
            && target != crate::common::constants::BPF_MAP_TYPE_HASH_OF_MAPS
        {
            continue;
        }
        // (a) sibling top-level map declaring the same struct.
        if let Some(idx) = def_struct_ids.iter().position(|id| *id == inner_id) {
            map_defs[i].inner_map_idx = Some(idx);
            info!(target: "app", "[BTF] Map '{}' inner_map_idx -> {} ('{}')",
                map_defs[i].name, idx, map_defs[idx].name);
            continue;
        }
        // (b) inline anonymous inner-map template — dedupe per struct id.
        if let Some(&existing) = synth_inner_by_struct.get(&inner_id) {
            map_defs[i].inner_map_idx = Some(existing);
            continue;
        }
        let Some(inner_t) = ctx.types.get(&inner_id) else {
            continue;
        };
        if inner_t.kind() != BTF_KIND_STRUCT {
            continue;
        }
        let ip = parse_map_struct_members(&ctx, inner_t);
        let inner_name = format!("{}.inner", map_defs[i].name);
        let Some(inner_md) = map_def_from_parsed(&ctx, inner_name, &ip) else {
            continue;
        };
        let new_idx = map_defs.len();
        info!(target: "app", "[BTF] Map '{}' inline inner_map_idx -> {} ('{}', Type: {}, ValSize: {})",
            map_defs[i].name, new_idx, inner_md.name, inner_md.type_, inner_md.value_size);
        map_defs.push(inner_md);
        map_defs[i].inner_map_idx = Some(new_idx);
        synth_inner_by_struct.insert(inner_id, new_idx);
    }

    Ok(map_defs)
}
