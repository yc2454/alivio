use anyhow::Result;
use goblin::elf::Elf;
use std::fs;
use std::path::Path;

use super::types::BpfMapDef;
use crate::common::constants;
use crate::parsing::btf;
use log::{debug, warn};

/// Load data sections as synthetic maps
pub fn load_data_section_maps<P: AsRef<Path>>(path: P) -> Result<Vec<BpfMapDef>> {
    let buf = fs::read(path)?;
    let elf = Elf::parse(&buf)?;

    // Pre-parse BTF once so we can attach `btf_val_type_id` to the
    // DATASEC for each synthetic data-section map. Without this,
    // SpecialField validation (spin_lock, rb_root, …) on `private(name)`
    // globals in `.bss.<name>` can't resolve any field because there's
    // no value-type BTF on the synthetic map.
    let btf_ctx = elf
        .section_headers
        .iter()
        .find_map(|sh| {
            if elf.shdr_strtab.get_at(sh.sh_name) == Some(".BTF") {
                let start = sh.sh_offset as usize;
                let end = start + sh.sh_size as usize;
                if end <= buf.len() {
                    return btf::parse_btf(&buf[start..end]).ok();
                }
            }
            None
        });

    let mut maps = vec![];

    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");

        // `.bss.<name>` mirrors `.data.<name>` / `.rodata.<name>` for
        // libbpf's `private(name)` macro idiom (see e.g.
        // `progs/refcounted_kptr.c`'s per-suite `.bss.A`/`.bss.B`/`.bss.C`).
        let is_data_section = name == ".rodata"
            || name == ".data"
            || name == ".bss"
            || name.starts_with(".rodata.")
            || name.starts_with(".data.")
            || name.starts_with(".bss.");

        if is_data_section && sh.sh_size > 0 {
            let initial_data = if sh.sh_type == constants::SHT_NOBITS {
                Some(vec![0u8; sh.sh_size as usize])
            } else {
                let start = sh.sh_offset as usize;
                let end = start + sh.sh_size as usize;
                if end <= buf.len() {
                    Some(buf[start..end].to_vec())
                } else {
                    None
                }
            };

            let extra_flags = if name.starts_with(".rodata") {
                constants::BPF_F_RDONLY_PROG
            } else {
                0
            };

            let btf_val_type_id = btf_ctx
                .as_ref()
                .and_then(|ctx| ctx.find_datasec(name));

            // `private(NAME) static struct foo __kptr * x` lives in a
            // synthetic `.data..NAME` (or `.bss..NAME`) datasec. Extract
            // the embedded kptr fields from the datasec's VAR entries
            // so `bpf_kptr_xchg(&x, …)` and the kptr-load typing path
            // see the same metadata as explicit `.maps`-section maps.
            let kptr_fields = btf_val_type_id
                .and_then(|id| btf_ctx.as_ref().map(|ctx| ctx.extract_datasec_kptr_fields(id)))
                .unwrap_or_default();

            maps.push(BpfMapDef {
                type_: constants::BPF_MAP_TYPE_ARRAY,
                key_size: 4,
                value_size: sh.sh_size as u32,
                max_entries: 1,
                map_flags: extra_flags,
                name: name.to_string(),
                btf_val_type_id,
                initial_data,
                inner_map_idx: None,
                kptr_fields,
            extern_var_offsets: Vec::new(),
            });
        }
    }

    Ok(maps)
}

/// Synthesize maps for libbpf-managed extern sections that don't appear as
/// real ELF sections but are described in BTF DATASEC. Today only `.kconfig`
/// is handled — these are scalar kernel-config externs declared with
/// `extern <type> NAME __kconfig;`. libbpf builds the map at load time and
/// patches `R_BPF_64_64` relocations against UND extern symbols into
/// `BPF_PSEUDO_MAP_VALUE` LD_IMM64s. We mirror that here so the lowerer sees
/// the LD_IMM64 + LDX pattern as a typed map-value access instead of a load
/// from address 0 (the unrelocated default).
///
/// `.ksyms` (typed kernel-symbol externs) is intentionally not handled — those
/// resolve via `BPF_PSEUDO_BTF_ID`, not `MAP_VALUE`.
pub fn load_btf_extern_maps<P: AsRef<Path>>(path: P) -> Result<Vec<BpfMapDef>> {
    let buf = fs::read(&path)?;
    let elf = Elf::parse(&buf)?;

    let btf_ctx = elf.section_headers.iter().find_map(|sh| {
        if elf.shdr_strtab.get_at(sh.sh_name) == Some(".BTF") {
            let start = sh.sh_offset as usize;
            let end = start + sh.sh_size as usize;
            if end <= buf.len() {
                return btf::parse_btf(&buf[start..end]).ok();
            }
        }
        None
    });

    let Some(ctx) = btf_ctx else {
        return Ok(vec![]);
    };

    let mut maps = vec![];
    let sec_name = ".kconfig";
    let Some(datasec_id) = ctx.find_datasec(sec_name) else {
        return Ok(maps);
    };
    let entries = ctx.datasec_entries(datasec_id);
    if entries.is_empty() {
        return Ok(maps);
    }

    // clang emits `.kconfig` DATASEC entries with offset=0; libbpf assigns
    // the real offsets at load time, sequentially with size-aligned packing.
    // We mirror that deterministically here — the actual values are unknown
    // at static-analysis time anyway, so as long as each var maps to a
    // distinct, in-bounds offset, loads through the synthesized map produce
    // ScalarValue (any) and verification proceeds.
    let mut cur_off: u32 = 0;
    let mut extern_var_offsets: Vec<(String, u32)> = Vec::new();
    for entry in &entries {
        let Some((name, _)) = ctx.var_info(entry.var_id) else {
            continue;
        };
        let size = entry.size.max(1);
        let align = size.next_power_of_two().min(8);
        let aligned = cur_off.div_ceil(align) * align;
        extern_var_offsets.push((name.to_string(), aligned));
        cur_off = aligned + size;
    }
    let value_size = cur_off.max(8);

    maps.push(BpfMapDef {
        type_: constants::BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size,
        max_entries: 1,
        map_flags: constants::BPF_F_RDONLY_PROG,
        name: sec_name.to_string(),
        btf_val_type_id: Some(datasec_id),
        initial_data: None,
        inner_map_idx: None,
        kptr_fields: Vec::new(),
        extern_var_offsets,
    });
    Ok(maps)
}

/// One `__ksym` extern variable (declared in the `.ksyms` BTF DATASEC).
/// Populated by `load_ksyms` and consumed by the relocation pass to emit
/// `RelocKind::Ksym` for `R_BPF_64_64` against UND ksym symbols.
#[derive(Clone, Debug)]
pub struct KsymInfo {
    /// Symbol name (e.g. `runqueues`, `bpf_prog_active`).
    pub name: String,
    /// Resolved struct/union/fwd name underlying the var's type chain,
    /// `None` for typeless / primitive ksyms (`extern const int X __ksym;`,
    /// `extern const void X __ksym;`).
    pub struct_name: Option<String>,
    /// True if any TYPE_TAG named `percpu` appears in the var's type chain
    /// (kernel `DECLARE_PER_CPU(...)` lowers to a `__percpu` tag).
    pub is_percpu: bool,
}

/// Extract `__ksym` extern declarations from the program's BTF `.ksyms`
/// DATASEC. Used by the relocation pass to type `R_BPF_64_64` against UND
/// ksym symbols as `BPF_PSEUDO_BTF_ID` (LDIMM64 src=3) loads with
/// resolved struct + percpu metadata.
pub fn load_ksyms<P: AsRef<Path>>(path: P) -> Result<Vec<KsymInfo>> {
    let buf = fs::read(&path)?;
    let elf = Elf::parse(&buf)?;

    let btf_ctx = elf.section_headers.iter().find_map(|sh| {
        if elf.shdr_strtab.get_at(sh.sh_name) == Some(".BTF") {
            let start = sh.sh_offset as usize;
            let end = start + sh.sh_size as usize;
            if end <= buf.len() {
                return btf::parse_btf(&buf[start..end]).ok();
            }
        }
        None
    });

    let Some(ctx) = btf_ctx else { return Ok(Vec::new()); };
    let Some(datasec_id) = ctx.find_datasec(".ksyms") else { return Ok(Vec::new()); };

    let mut out = Vec::new();
    for entry in ctx.datasec_entries(datasec_id) {
        let Some((name, var_type_id)) = ctx.var_info(entry.var_id) else { continue };
        let (struct_name, mut is_percpu) = ctx.classify_ksym_type(var_type_id);
        // Kernel `DECLARE_PER_CPU(...)` symbols carry the `__percpu`
        // TYPE_TAG only in vmlinux/module BTF — programs that import them
        // via `extern const T X __ksym;` see a plain T in their own BTF.
        // We don't ship vmlinux BTF, so fall back to a static allowlist
        // of the known percpu ksyms exercised by the test corpus.
        if !is_percpu && is_known_percpu_ksym(name) {
            is_percpu = true;
        }
        out.push(KsymInfo {
            name: name.to_string(),
            struct_name,
            is_percpu,
        });
    }
    Ok(out)
}

/// Static allowlist of known kernel/testmod ksym names that are
/// `__percpu`-tagged in vmlinux/module BTF. Mirrors the kernel's
/// per-cpu declarations exercised by the upstream selftest corpus —
/// extending this list is the right move whenever a new test imports
/// a percpu kernel symbol.
fn is_known_percpu_ksym(name: &str) -> bool {
    matches!(
        name,
        "runqueues"
            | "bpf_prog_active"
            | "bpf_testmod_ksym_percpu"
            // `DEFINE_PER_CPU(int, bpf_task_storage_busy)` in
            // kernel/bpf/bpf_task_storage.c — declared in selftests as
            // `extern const int bpf_task_storage_busy __ksym` (no
            // program-side `__percpu` annotation), so the percpu flag
            // can only come from this allowlist.
            | "bpf_task_storage_busy"
    )
}

pub fn load_maps<P: AsRef<Path>>(path: P) -> Result<Vec<BpfMapDef>> {
    let buf = fs::read(&path)?;
    let elf = Elf::parse(&buf)?;
    let mut maps = Vec::new();
    let mut btf_data = None;

    for (i, sh) in elf.section_headers.iter().enumerate() {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            if name == "maps" || name == ".maps" {
                let start = sh.sh_offset as usize;
                let end = start + sh.sh_size as usize;

                if end > buf.len() {
                    warn!("'maps' section extends beyond file buffer");
                    continue;
                }

                let section_data = &buf[start..end];

                for sym in elf.syms.iter() {
                    if sym.st_shndx == i
                        && let Some(map_name) = elf.strtab.get_at(sym.st_name)
                    {
                        let offset = sym.st_value as usize;
                        let map_size = if sym.st_size > 0 {
                            sym.st_size as usize
                        } else {
                            28
                        };
                        // Valueless maps (RINGBUF, ARENA, …) have BTF defs as
                        // small as 16 bytes (just `type` + `max_entries`); the
                        // legacy 20-byte minimum dropped them silently. Lower
                        // the floor to one u32 (the type field) and let the
                        // bounded `read_u32` helper cover any short tail.
                        if offset + 4 <= section_data.len() {
                            let read_len = std::cmp::min(map_size, section_data.len() - offset);
                            let b = &section_data[offset..offset + read_len];

                            let inner_map_idx = if read_len >= 24 {
                                Some(u32::from_le_bytes(b[20..24].try_into().unwrap()) as usize)
                            } else {
                                None
                            };

                            // Modern BTF-described maps may omit the
                            // tail fields of the legacy `bpf_map_def`.
                            // Read each field only if `read_len` covers it.
                            let read_u32 = |start: usize| {
                                if read_len >= start + 4 {
                                    u32::from_le_bytes(b[start..start + 4].try_into().unwrap())
                                } else {
                                    0
                                }
                            };
                            maps.push(BpfMapDef {
                                name: map_name.to_string(),
                                type_: read_u32(0),
                                key_size: read_u32(4),
                                value_size: read_u32(8),
                                max_entries: read_u32(12),
                                map_flags: read_u32(16),
                                btf_val_type_id: None,
                                initial_data: None,
                                inner_map_idx,
                                kptr_fields: Vec::new(),
            extern_var_offsets: Vec::new(),
                            });
                        }
                    }
                }
            } else if name == ".BTF" {
                let start = sh.sh_offset as usize;
                let end = start + sh.sh_size as usize;
                if end <= buf.len() {
                    btf_data = Some(&buf[start..end]);
                }
            }
        }
    }

    let needs_btf = maps.is_empty() || maps.iter().any(|m| m.value_size == 0);
    if needs_btf
        && let Some(btf_bytes) = btf_data
        && let Ok(btf_maps) = btf::parse_btf_map_defs(btf_bytes)
    {
        if maps.is_empty() {
            maps = btf_maps;
        } else {
            for m in &mut maps {
                if let Some(btf_m) = btf_maps.iter().find(|bm| bm.name == m.name) {
                    // Always update type_ and max_entries from BTF when available
                    if m.value_size == 0 {
                        m.value_size = btf_m.value_size;
                        m.key_size = btf_m.key_size;
                    }
                    if m.type_ == 0 {
                        m.type_ = btf_m.type_;
                    }
                    if m.max_entries == 0 {
                        m.max_entries = btf_m.max_entries;
                    }
                    // The legacy `bpf_map_def` section can't carry a value
                    // type id, so the BTF-described copy is the only source
                    // for it. Without this, MapValueSpecial validators
                    // (spin_lock, timer, list_head, rb_root) reject every
                    // ARRAY/HASH map produced by libbpf-style `__type(value, …)`
                    // declarations with "no value-type BTF".
                    if m.btf_val_type_id.is_none() {
                        m.btf_val_type_id = btf_m.btf_val_type_id;
                    }
                    if m.kptr_fields.is_empty() && !btf_m.kptr_fields.is_empty() {
                        m.kptr_fields = btf_m.kptr_fields.clone();
                    }
                    // Inner-map mapping for ARRAY_OF_MAPS / HASH_OF_MAPS:
                    // legacy bpf_map_def carries inner_map_idx in its
                    // tail; modern BTF-described maps populate it via
                    // parse_btf_map_defs's `__array(values, struct T)`
                    // post-pass. Skip here — `btf_m.inner_map_idx` is
                    // an index into the BTF-side vector whose order
                    // differs from the live `maps` (legacy section is
                    // symbol-order, BTF is HashMap-order). A second
                    // pass below translates by name into the live
                    // vector's index space.
                    let _ = btf_m;
                    // BTF-described maps encode `__uint(map_flags, …)` in BTF;
                    // the legacy `bpf_map_def` slot in the .maps section reads
                    // as 0. Trust BTF when the section side is unset.
                    if m.map_flags == 0 {
                        m.map_flags = btf_m.map_flags;
                    }
                }
            }
        }
    }

    for m in &mut maps {
        if m.value_size == 0
            && matches!(
                m.type_,
                constants::BPF_MAP_TYPE_ARRAY_OF_MAPS | constants::BPF_MAP_TYPE_HASH_OF_MAPS
            )
        {
            // Legacy map of maps without inner map info. Fallback to 4 for basic analysis.
            m.value_size = 4;
        }
    }

    // Translate BTF-side `inner_map_idx` into live `maps`-vector
    // indices. parse_btf_map_defs's post-pass records inner_map_idx as
    // an index into its OWN HashMap-iterated output; that order
    // generally differs from `maps` (which is legacy-symbol-order
    // post-merge). Re-resolve by matching the BTF inner-map's name
    // against `maps[].name`. Always run for ARRAY_OF_MAPS/HASH_OF_MAPS
    // maps that have a BTF-side entry with `inner_map_idx = Some(_)`
    // — the legacy section parser unconditionally reads bytes 20..24
    // and yields `Some(0)` garbage for modern BTF-described maps, so a
    // pre-existing `Some` doesn't mean the value is correct.
    if let Some(btf_bytes) = btf_data
        && let Ok(btf_maps) = btf::parse_btf_map_defs(btf_bytes)
    {
        // For each map in the live `maps` vector that's a map-of-maps,
        // look up the matching BTF entry by name, then translate its
        // inner_map_idx (BTF-order) → name → live-order.
        let live_index_by_name: std::collections::HashMap<&str, usize> = maps
            .iter()
            .enumerate()
            .map(|(i, m)| (m.name.as_str(), i))
            .collect();
        // Snapshot just the resolved live indices first to avoid the
        // outer mutable borrow of `maps` while we look up by name.
        // `to_append` collects BTF-synthesized inline inner-map
        // templates: they have no ELF symbol so
        // no live `maps` entry exists — append them and point the outer
        // at the appended index. Without this the outer keeps
        // value_size 4 (the of-maps fd slot) and indexed inner-value
        // loads `value[hash % N]` are rejected as OOB.
        let mut updates: Vec<(usize, usize)> = Vec::new();
        let mut to_append: Vec<BpfMapDef> = Vec::new();
        let mut appended_by_name: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for (i, m) in maps.iter().enumerate() {
            if !matches!(
                m.type_,
                constants::BPF_MAP_TYPE_ARRAY_OF_MAPS | constants::BPF_MAP_TYPE_HASH_OF_MAPS
            ) {
                continue;
            }
            let Some(btf_m) = btf_maps.iter().find(|bm| bm.name == m.name) else {
                continue;
            };
            let Some(btf_inner_idx) = btf_m.inner_map_idx else {
                continue;
            };
            let Some(btf_inner) = btf_maps.get(btf_inner_idx) else {
                continue;
            };
            if let Some(&live_idx) = live_index_by_name.get(btf_inner.name.as_str()) {
                updates.push((i, live_idx));
            } else if let Some(&aidx) = appended_by_name.get(&btf_inner.name) {
                updates.push((i, aidx));
            } else {
                let new_idx = maps.len() + to_append.len();
                appended_by_name.insert(btf_inner.name.clone(), new_idx);
                to_append.push(btf_inner.clone());
                updates.push((i, new_idx));
            }
        }
        maps.extend(to_append);
        for (outer, inner) in updates {
            maps[outer].inner_map_idx = Some(inner);
        }
    }

    for (i, m) in maps.iter().enumerate() {
        debug!(
            "Map [{}]: name={}, type={}, key_size={}, value_size={}, max_entries={}",
            i, m.name, m.type_, m.key_size, m.value_size, m.max_entries
        );
    }

    Ok(maps)
}
