use crate::analysis::machine::error::VerificationError;
// src/analysis/transfer/memory/map.rs

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use crate::ast::MapLoadKind;
use crate::common::constants;
use crate::domains::numeric::NumericDomain;
use crate::parsing::elf::{BpfMapDef, KptrField, KptrFieldKind};
use log::error;

/// Outcome of overlapping a constant `[off, off+size)` access against a
/// map's kptr fields.
pub enum KptrAccessOutcome<'a> {
    /// Access doesn't touch any kptr field.
    None,
    /// Access exactly matches a kptr field at `field.offset`, size 8,
    /// 8-byte aligned. Caller proceeds and (for loads) types the dst as
    /// `PtrToMapKptrOrNull`; for stores, may reject if the field is
    /// referenced (Ref/Rcu/Percpu).
    Hit(&'a KptrField),
    /// Access overlaps a kptr field with size != 8.
    BadSize { _field_off: u32, size: i64 },
    /// Access overlaps a kptr field with a misaligned start offset
    /// (i.e., `off != field.offset`, but the access window intersects
    /// the kptr's 8-byte slot).
    Misaligned { off: i64, expected: u8 },
}

/// Check a constant-offset access against `map_def.kptr_fields`.
/// Returns the kind of overlap, or `None` if no kptr field is touched.
pub fn classify_kptr_access(map_def: &BpfMapDef, off: i64, size: i64) -> KptrAccessOutcome<'_> {
    if map_def.kptr_fields.is_empty() {
        return KptrAccessOutcome::None;
    }
    let access_end = off + size;
    for f in &map_def.kptr_fields {
        let f_off = f.offset as i64;
        let f_end = f_off + 8; // kptr fields are always 8-byte pointers
        if access_end <= f_off || off >= f_end {
            continue;
        }
        // Some overlap with this kptr slot.
        if off == f_off && size == 8 {
            return KptrAccessOutcome::Hit(f);
        }
        if off == f_off {
            // Right offset, wrong size (e.g., 4-byte read of a kptr).
            return KptrAccessOutcome::BadSize {
                _field_off: f.offset,
                size,
            };
        }
        // Wrong offset — partial overlap. Kernel reports
        // "kptr access misaligned expected=8 off=N" using the
        // *access* offset relative to the map value.
        return KptrAccessOutcome::Misaligned {
            off,
            expected: 8,
        };
    }
    KptrAccessOutcome::None
}

/// Resolve the constant access offset for a `PtrToMapValue` access if
/// possible: prefer the type-carried `map_off`, fall back to a domain
/// lookup that pins both bounds to the same value.
pub fn resolve_const_map_off(
    state: &State,
    base: Reg,
    map_off_opt: Option<i64>,
    insn_off: i16,
) -> Option<i64> {
    if let Some(off) = map_off_opt {
        return Some(off + insn_off as i64);
    }
    if let NumericDomain::Interval(ref ivl) = state.domain
        && let Some(p) = ivl.get_ptr_offset(base)
        && p.min_offset() == p.max_offset()
    {
        return Some(p.min_offset() + insn_off as i64);
    }
    None
}

/// Apply kptr-field rules to a constant- or variable-offset access on a
/// `PtrToMapValue`. Pure validator — fails `env` on bad cases (size,
/// alignment, varoff, store-to-referenced) and is a no-op on a clean
/// kptr-field hit. Generic bounds checking still runs after this.
pub fn check_kptr_field_access(
    env: &mut VerifierEnv,
    state: &State,
    map_def: &BpfMapDef,
    map_idx: usize,
    base: Reg,
    map_off_opt: Option<i64>,
    insn_off: i16,
    size: i64,
    pc: usize,
    is_store: bool,
) {
    if map_def.kptr_fields.is_empty() {
        return;
    }
    if let Some(final_off) = resolve_const_map_off(state, base, map_off_opt, insn_off) {
        match classify_kptr_access(map_def, final_off, size) {
            KptrAccessOutcome::None => {}
            KptrAccessOutcome::Hit(field) => {
                if is_store {
                    match field.kind {
                        KptrFieldKind::Ref | KptrFieldKind::Rcu | KptrFieldKind::Percpu => {
                            env.fail(VerificationError::KptrStoreToReferenced {
                                pc,
                                off: final_off,
                            });
                        }
                        KptrFieldKind::Uptr => {
                            // `__uptr` slots are userspace-owned. BPF may
                            // read but never write — the kernel rejects any
                            // store regardless of the source value (NULL,
                            // scalar, or pointer alike).
                            env.fail(VerificationError::UptrStoreDisallowed {
                                pc,
                                off: final_off,
                            });
                        }
                        KptrFieldKind::Unref => {
                            // Direct stores to unreferenced kptr slots
                            // are allowed in the kernel — but the stored
                            // value must be a compatible BTF pointer or
                            // NULL. Source-side typing is enforced in
                            // enforced alongside `bpf_kptr_xchg`.
                        }
                    }
                }
            }
            KptrAccessOutcome::BadSize { _field_off: _, size } => {
                env.fail(VerificationError::KptrAccessSizeMustBeDW {
                    pc,
                    off: final_off,
                    size,
                });
            }
            KptrAccessOutcome::Misaligned { off, expected } => {
                env.fail(VerificationError::KptrAccessMisaligned { pc, off, expected });
            }
        }
        return;
    }

    // Variable offset: bound the access window if possible, else assume
    // it could land anywhere in the map value.
    let (lo, hi) = if let NumericDomain::Interval(ref ivl) = state.domain
        && let Some(p) = ivl.get_ptr_offset(base)
    {
        (
            p.min_offset() + insn_off as i64,
            p.max_offset() + insn_off as i64 + size,
        )
    } else {
        (0, map_def.value_size as i64)
    };
    if varoff_overlaps_kptr(map_def, lo, hi) {
        env.fail(VerificationError::KptrAccessVariableOffset { pc, map_idx });
    }
}

/// Returns the kptr field exactly hit by a constant 8-byte 8-aligned
/// access at `off`, or `None`. Used by load typing to produce
/// `PtrToMapKptrOrNull`.
pub fn kptr_field_at(map_def: &BpfMapDef, off: i64, size: i64) -> Option<&KptrField> {
    if size != 8 {
        return None;
    }
    map_def
        .kptr_fields
        .iter()
        .find(|f| f.offset as i64 == off)
}

/// True iff a variable-offset access window `[lo, hi)` could overlap any
/// kptr field in `map_def`. Used to reject variable-offset accesses to
/// map values that contain kptrs (the kernel forbids these unconditionally
/// because the access could land on a kptr slot).
pub fn varoff_overlaps_kptr(map_def: &BpfMapDef, lo: i64, hi: i64) -> bool {
    for f in &map_def.kptr_fields {
        let f_off = f.offset as i64;
        let f_end = f_off + 8;
        if hi > f_off && lo < f_end {
            return true;
        }
    }
    false
}

pub fn check_map_rw(env: &mut VerifierEnv, map_idx: usize, pc: usize, is_write: bool) {
    let flag_to_check = if is_write {
        constants::BPF_F_RDONLY_PROG
    } else {
        constants::BPF_F_WRONLY_PROG
    };
    let ctx = env.ctx;
    if let Some(map_def) = ctx.map_defs.get(map_idx) {
        if map_def.map_flags == flag_to_check {
            error!("Map read is forbidden!");
            env.fail(VerificationError::MapLoadForbidden { pc, map_idx });
        }
    } else {
        error!("Map not found!");
        env.fail(VerificationError::MapNotFound { pc, map_idx })
    }
}

pub fn check_btf_fields_access(
    env: &mut VerifierEnv,
    pc: usize,
    final_offset: i64,
    access_end: i64,
    size: i64,
    map_limit: i64,
    btf_id: u32,
) {
    let btf_fields = env.ctx.btf.find_special_fields(btf_id);
    for field in btf_fields {
        let field_end = field.offset + field.size;

        if final_offset < field_end.into() && access_end > field.offset.into() {
            error!("Cannot access BTF field");
            env.fail(VerificationError::UnsafeMapLoad {
                pc,
                off: final_offset,
                size,
                limit: map_limit,
            });
        }
    }
}

pub fn check_map_access(
    env: &mut VerifierEnv,
    state: &State,
    map_limit: i64,
    map_off_opt: Option<i64>,
    map_idx: usize,
    base: Reg,
    map_def: &BpfMapDef,
    insn_off: i16,
    size: i64,
    pc: usize,
) {
    // For interval domain, try to use PtrOffset for bounds checking
    if let NumericDomain::Interval(ref ivl) = state.domain {
        if interval_check_map_access(
            env, state, ivl, map_limit, map_idx, base, map_def, insn_off, size, pc,
        ) {
            return;
        }
    }

    zone_check_map_access(
        env,
        state,
        map_limit,
        map_off_opt,
        map_idx,
        base,
        map_def,
        insn_off,
        size,
        pc,
    );
}

fn interval_check_map_access(
    env: &mut VerifierEnv,
    state: &State,
    ivl: &crate::domains::interval::IntervalState,
    map_limit: i64,
    _map_idx: usize,
    base: Reg,
    map_def: &BpfMapDef,
    insn_off: i16,
    size: i64,
    pc: usize,
) -> bool {
    if let Some(ptr_off) = ivl.get_ptr_offset(base) {
        // Use PtrOffset to get offset range from buffer start
        let min_off = ptr_off.min_offset() + (insn_off as i64);
        let max_off = ptr_off.max_offset() + (insn_off as i64) + size;
        if std::env::var("ZOVIA_TRACE_MAP_ACCESS").ok().as_deref() == Some("1") {
            eprintln!(
                "[MAP_ACCESS] pc={} base={:?} ptr_off=[{},{}] insn_off={} size={} -> min_off={} max_off={} limit={} btf_id={:?}",
                pc, base, ptr_off.min_offset(), ptr_off.max_offset(),
                insn_off, size, min_off, max_off, map_limit, map_def.btf_val_type_id,
            );
            if let Some(btf_id) = map_def.btf_val_type_id {
                let sf = env.ctx.btf.find_special_fields(btf_id);
                eprintln!("[MAP_ACCESS]   special_fields(btf_id={}) = {:?}", btf_id, sf);
            }
        }

        // enforce value_size bounds even when the map carries a
        // BTF value-type. The special-fields check below is additive — a
        // spin_lock overlap is one rejection reason, but plain OOB is another.
        if !(min_off >= 0 && max_off <= map_limit) {
            // BCF map-region refinement (α template 4b case iii).
            if try_bcf_refine_map(env, state, base, insn_off as i64, size, map_limit) {
                return true;
            }
            error!(
                "Unsafe variable map access at pc {}: range [{}, {}], limit {}",
                pc, min_off, max_off, map_limit
            );
            env.fail(VerificationError::UnsafeMapLoad {
                pc,
                off: min_off,
                size,
                limit: map_limit,
            });
            return true;
        }

        if let Some(btf_id) = map_def.btf_val_type_id {
            check_btf_fields_access(env, pc, min_off, max_off, size, map_limit, btf_id);
        }
        return true;
    }
    false
}

fn zone_check_map_access(
    env: &mut VerifierEnv,
    state: &State,
    map_limit: i64,
    map_off_opt: Option<i64>,
    map_idx: usize,
    base: Reg,
    map_def: &BpfMapDef,
    insn_off: i16,
    size: i64,
    pc: usize,
) {
    // Zone domain or interval without PtrOffset: use scalar bounds
    let (dbm_min, dbm_max) = state.domain.get_interval(base);
    if dbm_min != i64::MIN && dbm_max != i64::MAX {
        let min_val = dbm_min;
        let max_val = dbm_max;
        let access_start = min_val + (insn_off as i64);
        let access_end = max_val + (insn_off as i64) + size;

        // enforce value_size first; BTF special-field overlap is
        // additive, not a substitute.
        if !(access_start >= 0 && access_end <= map_limit) {
            if try_bcf_refine_map(env, state, base, insn_off as i64, size, map_limit) {
                return;
            }
            error!(
                "Unsafe variable map access at pc {}: range [{}, {}], limit {}",
                pc, access_start, access_end, map_limit
            );
            env.fail(VerificationError::UnsafeMapLoad {
                pc,
                off: access_start,
                size,
                limit: map_limit,
            });
            return;
        }

        if let Some(btf_id) = map_def.btf_val_type_id {
            check_btf_fields_access(
                env,
                pc,
                insn_off.into(),
                access_end,
                size,
                map_limit,
                btf_id,
            );
        }
    } else if let Some(fixed_off) = map_off_opt {
        let final_offset = fixed_off + (insn_off as i64);
        let access_end = final_offset + size;

        if !(final_offset >= 0 && access_end <= map_limit) {
            error!(
                "Unsafe map access at pc {}: off {} limit {}",
                pc, final_offset, map_limit
            );
            env.fail(VerificationError::UnsafeMapAccess { pc, size, map_idx });
            return;
        }

        if let Some(btf_id) = map_def.btf_val_type_id {
            check_btf_fields_access(env, pc, final_offset, access_end, size, map_limit, btf_id);
        }
    } else {
        if try_bcf_refine_map(env, state, base, insn_off as i64, size, map_limit) {
            return;
        }
        error!("Unbounded variable map access at pc {}", pc);
        env.fail(VerificationError::UnsafeMapLoad {
            pc,
            off: insn_off.into(),
            size,
            limit: map_limit,
        });
    }
}

/// Helper: try the BCF map-region refinement and stash the proof on
/// `env.bcf_proofs` on success. Returns `true` if the rejection should
/// be suppressed. Mirrors `try_bcf_refine_stack` in [`memory::stack`].
fn try_bcf_refine_map(
    env: &mut VerifierEnv,
    state: &State,
    base: Reg,
    insn_off: i64,
    size: i64,
    map_limit: i64,
) -> bool {
    let bcf_debug = std::env::var("ZOVIA_TRACE_BCF_REFINE").ok().as_deref() == Some("1");
    if state.bcf.is_none() {
        if bcf_debug { eprintln!("[REFINE] pc={} bcf=None -> skip", state.pc); }
        return false;
    }
    let size_reg = env.bcf_size_reg;
    // Mirror kernel `bcf_refine_access_bound` (verifier.c:5455-5468):
    // include ptr regno in reg_masks ONLY when its var_off is non-const,
    // and include size_regno ONLY when its var_off is non-const.
    // Kernel `tnum_is_const(ptr_reg->var_off)` analog: use ptr_off range
    // from the interval domain. min == max ⇒ no variable contribution.
    // var_off_contributor is unreliable here because zovia's spill/fill
    // doesn't always clear it when a fresh const-offset map_value is
    // filled.
    let ptr_is_const = match state.domain.as_interval().and_then(|i| i.get_ptr_offset(base)) {
        Some(ptr_off) => ptr_off.min_offset() == ptr_off.max_offset(),
        None => true,
    };
    if bcf_debug {
        let po = state.domain.as_interval().and_then(|i| i.get_ptr_offset(base));
        eprintln!("[REFINE-TARGETS] pc={} base={:?} ptr_is_const={} ptr_off=[{:?}..{:?}]",
                  state.pc, base, ptr_is_const,
                  po.as_ref().map(|p| p.min_offset()), po.as_ref().map(|p| p.max_offset()));
    }
    let mut target_regs: Vec<Reg> = Vec::new();
    if !ptr_is_const {
        target_regs.push(base);
    }
    if let Some(sr) = size_reg {
        // Kernel also gates size_reg inclusion on non-const; for zovia,
        // a missing bcf_expr cache means size is const for refine
        // purposes (case (ii)/(iv) below handles it).
        if state.domain.get_fixed_value(sr).is_none() {
            target_regs.push(sr);
        }
    }
    if target_regs.is_empty() {
        // Both const → no walker needed; pass empty so suffix_base_pc
        // returns None and refine uses keep-all (kernel-faithful too:
        // kernel returns bcf_prove_unreachable in this branch).
    }
    let landed = state
        .history_idx
        .and_then(|hidx| crate::analysis::flow::precision::bcf_suffix_base_pc_and_cache_id(env, hidx, state.parent_cache_id, &target_regs));
    let base_pc = landed.map(|(pc, _)| pc);
    if bcf_debug {
        eprintln!("[REFINE] pc={} base={:?} insn_off={} size={} limit={} size_reg={:?} base_pc={:?} parent_cid={:?} history_idx={:?}",
                  state.pc, base, insn_off, size, map_limit, size_reg, base_pc,
                  state.parent_cache_id, state.history_idx);
    }
    let legacy_ok = crate::refinement::refine_map::try_refine_map_access(
        state, base, insn_off, size, map_limit, size_reg, base_pc, None,
    );
    // Kernel bcf_track replay-rebuild variant (ADDITIVE): re-execute
    // base→reject with a fresh bcf so the path conds AND the refine
    // predicate come from ONE replay expr table — the kernel's actual
    // goal-formation semantics. Required for loop-wrapping suffixes where
    // the live-state goal keeps pre-base chains and over-spanning conds
    // (see replay_to_reject doc).
    // base_pc=None: the replayed sym's path_conds ARE exactly the suffix,
    // no filtering wanted. Dedupe by cond_hash before pushing.
    // Never nest replays: a mid-replay access failure runs the legacy
    // refine (needed for the replayed path to continue past its own
    // discharged accesses) but must not spawn a recursive re-execution.
    let mut replay_variants: Vec<crate::refinement::refine_stack::RefineOk> = Vec::new();
    if !env.replay_mode {
        if let Some((_, cid)) = landed {
            // Two anchor shapes, both additive:
            // - plain (anchor = the base cache entry itself): matches the
            //   kernel when the base's regs weren't cache-mutated;
            // - parent-anchored (execute from the base's parent, bcf reset
            //   at the base boundary): rebuilds pristine operand bounds
            //   where caching widened them (kernel replays st->parent
            //   snapshots, which are never widened).
            // Variant order is FIXED so existing bundles stay
            // prefix-stable: the two plain/parent shapes first, then the
            // slot-share shapes (kernel bcf_track bt slot-demand
            // materialization — a loop-invariant stack slot filled per
            // iteration shares ONE var), then the ancestor-cache LADDER:
            // the kernel's backtrack_states walks parent STATES and its
            // base freely crosses call/loop boundaries, so one replay per
            // ancestor rung offers each boundary; additive + hash-deduped
            // like the rung-0 shapes. Deep rungs run the slot-share shapes
            // only (multi-iteration windows re-fill loop-invariant slots;
            // kernel shares ONE var). Pre-solve hash dedupe keeps the
            // ladder's cvc5 cost bounded to novel goals.
            let mut rung_cids: Vec<u32> = vec![cid];
            {
                let mut cur =
                    env.state_by_cache_id(cid).and_then(|(_, s)| s.parent_cache_id);
                while let Some(c) = cur {
                    if rung_cids.len() >= 12 {
                        break;
                    }
                    rung_cids.push(c);
                    cur = env.state_by_cache_id(c).and_then(|(_, s)| s.parent_cache_id);
                }
            }
            // Kernel backtrack_states walks the CURRENT descent's parent
            // states (st->parent of the live state) — on post-marking
            // instances those are the FRESH caches of this lineage, which
            // the landed cache's stored creation-time ancestry can skip
            // entirely. Offer one rung per dynamic-ancestry cache as
            // well (ADDITIVE, appended after the fossil rungs so existing
            // bundle order is prefix-stable); stop where the dynamic chain
            // joins the fossil one. Deep-rung policy (share-only) + the
            // pre-solve hash dedupe bound the extra cvc5 cost.
            if let Some(pcid) = state.parent_cache_id {
                let mut cur = Some(pcid);
                let mut extra = 0;
                while let Some(c) = cur {
                    if extra >= 12 || rung_cids.contains(&c) {
                        break;
                    }
                    rung_cids.push(c);
                    extra += 1;
                    cur = env.state_by_cache_id(c).and_then(|(_, s)| s.parent_cache_id);
                }
            }
            if bcf_debug {
                let rung_desc: Vec<String> = rung_cids
                    .iter()
                    .map(|c| {
                        env.state_by_cache_id(*c)
                            .map(|(_, s)| format!("cid={} pc={} first={:?}", c, s.pc, s.first_insn_idx))
                            .unwrap_or_else(|| format!("cid={} <gone>", c))
                    })
                    .collect();
                eprintln!("[REFINE-RUNGS] pc={} rungs=[{}]", state.pc, rung_desc.join(" | "));
            }
            let mut known: std::collections::HashSet<u64> =
                env.bcf_proofs.iter().map(|e| e.cond_hash).collect();
            for (ri, rcid) in rung_cids.iter().enumerate() {
                // Third tuple slot = reset_at_crossing (see replay_to_reject):
                // the kernel's base can be a checkpoint on the CURRENT
                // lineage whose segment starts at a LATER re-arrival at the
                // rung's pc (zovia may never have cached there — adds are
                // cadence-gated). Offer the last two crossings per rung,
                // share-only, plain-anchor (ADDITIVE; crossings absent →
                // replay_to_reject bails to None).
                let variants: &[(bool, bool, Option<usize>)] = if ri == 0 {
                    &[
                        (false, false, None),
                        (true, false, None),
                        (false, true, None),
                        (true, true, None),
                        (false, true, Some(1)),
                        (false, true, Some(2)),
                        (false, true, Some(3)),
                        (false, true, Some(4)),
                    ]
                } else {
                    &[
                        (false, true, None),
                        (true, true, None),
                        (false, true, Some(1)),
                        (false, true, Some(2)),
                        (false, true, Some(3)),
                        (false, true, Some(4)),
                    ]
                };
                for &(anchor_at_parent, share_slot_vars, crossing) in variants {
                    if let Some(rst) = crate::refinement::emit::replay_to_reject(
                        env, *rcid, anchor_at_parent, share_slot_vars, crossing, None,
                    ) {
                        if let Some(ok) = crate::refinement::refine_map::try_refine_map_access(
                            &rst, base, insn_off, size, map_limit, size_reg, None,
                            Some(&known),
                        ) {
                            if bcf_debug {
                                eprintln!(
                                    "[REFINE] pc={} replay-variant(rung={} parent={} share={} cross={:?}) proof_bytes={}",
                                    state.pc, ri, anchor_at_parent, share_slot_vars, crossing,
                                    ok.proof_bytes.len()
                                );
                            }
                            known.insert(crate::refinement::canonical_hash::hash_expr(
                                ok.goal_root,
                                &ok.sym.exprs,
                            ));
                            replay_variants.push(ok);
                        }
                    }
                }
            }
            // Deep-path crossing cuts: the kernel base can be a segment
            // start (a per-iteration checkpoint pc) EARLIER than any
            // on-lineage cache of that pc — reachable only by cutting a
            // DEEP rung's long path at crossings of the OTHER rungs' pcs.
            // One replay per (distinct rung pc × last-4 crossings) on the
            // deepest rung's path; share-only; hash-dedupe bounds cost.
            if let Some(&deep_cid) = rung_cids.last() {
                let mut cut_pcs: Vec<usize> = rung_cids
                    .iter()
                    .filter_map(|c| env.state_by_cache_id(*c).map(|(_, s)| s.pc))
                    .collect();
                cut_pcs.sort_unstable();
                cut_pcs.dedup();
                for cut_pc in cut_pcs {
                    for k in 1..=4usize {
                        if let Some(rst) = crate::refinement::emit::replay_to_reject(
                            env, deep_cid, false, true, Some(k), Some(cut_pc),
                        ) {
                            if let Some(ok) = crate::refinement::refine_map::try_refine_map_access(
                                &rst, base, insn_off, size, map_limit, size_reg, None,
                                Some(&known),
                            ) {
                                if bcf_debug {
                                    eprintln!(
                                        "[REFINE] pc={} deep-cut(pc={} k={}) proof_bytes={}",
                                        state.pc, cut_pc, k, ok.proof_bytes.len()
                                    );
                                }
                                known.insert(crate::refinement::canonical_hash::hash_expr(
                                    ok.goal_root,
                                    &ok.sym.exprs,
                                ));
                                replay_variants.push(ok);
                            }
                        }
                    }
                }
            }
        }
    }
    let attempts: Vec<(bool, _)> = legacy_ok
        .into_iter()
        .map(|o| (false, o))
        .chain(replay_variants.into_iter().map(|o| (true, o)))
        .collect();
    if attempts.is_empty() {
        if bcf_debug { eprintln!("[REFINE] pc={} try_refine_map_access -> None", state.pc); }
        return false;
    }
    // Kernel bcf_refine TRACKING-mode guard (verifier.c:25153-25157): during
    // bcf_track's replay, a nested refine only runs refine_cb (the state
    // refinement, so the replayed path continues) and returns BEFORE the
    // bundle-discharge attempt AND before the parents children_unsafe
    // marking loop. Refine outcome (continue past the access) is
    // preserved; only the emission side effects are gated.
    if env.replay_mode {
        return true;
    }
    let mut emitted = false;
    for (is_replay_variant, ok) in attempts {
    if bcf_debug { eprintln!("[REFINE] pc={} SUCCESS proof_bytes={}", state.pc, ok.proof_bytes.len()); }
    let entry = crate::refinement::bundle::RefineEntry::new(
        ok.goal_root,
        ok.sym.exprs,
        ok.proof_bytes,
        crate::refinement::bundle::BCF_BUNDLE_KIND_REFINE,
    );
    log::info!(
        target: "app",
        "[bcf] refined map-OOB at base={:?} insn_off={} size={} (size_reg={:?}) limit={}: cvc5 proof {} bytes (hash {:016x})",
        base, insn_off, size, size_reg, map_limit, entry.proof_bytes.len(), entry.cond_hash
    );
    if let Ok(prefix) = std::env::var("ZOVIA_BCF_DUMP_PROOF") {
        let idx = env.bcf_proofs.len();
        let path = format!("{}.{}.bcf", prefix, idx);
        if let Err(e) = std::fs::write(&path, &entry.proof_bytes) {
            log::warn!(target: "app", "[bcf] proof dump to {} failed: {}", path, e);
        } else {
            log::info!(target: "app", "[bcf] dumped raw proof to {}", path);
        }
    }
    if std::env::var("ZOVIA_BCF_CENSUS").ok().as_deref() == Some("1") {
        crate::refinement::emit::unreachable::census_log(
            "refine_map", state.pc, -1, -1, entry.cond_hash,
            env.bcf_proofs.iter().any(|e| e.cond_hash == entry.cond_hash),
        );
    }
    // Legacy entries push unconditionally (pre-existing behavior — bundle
    // bytes for every currently-passing object stay identical). The
    // replay variant is ADDITIVE and dedupes by canonical hash: on
    // straight-line suffixes it coincides with the legacy goal and must
    // not double the bundle.
    if !is_replay_variant
        || !env.bcf_proofs.iter().any(|e| e.cond_hash == entry.cond_hash)
    {
        env.bcf_proofs.push(entry);
    }
    emitted = true;
    } // end for attempts
    let _ = emitted;
    // Mirror kernel `bcf_refine` parent-marking (verifier.c:24904-24921):
    // every cached ancestor on this refinement's backtrack suffix is no
    // longer prune-safe, because a later arrival that would otherwise
    // subsume against it may reach the same reject via a DIFFERENT path
    // and need its own (different-hash) discharge entry — the kernel sets
    // `children_unsafe=1` and exempts such ancestors from subsumption.
    // Branch-side refinement (`refine_unreachable`) calls this in
    // `branch/mod.rs`; the map/stack refinements need it too.
    crate::analysis::flow::pruning::cache::mark_path_children_unsafe(env, state, landed.map(|(_, cid)| cid));
    true
}

pub(crate) fn transfer_map_load(
    env: &mut VerifierEnv,
    mut state: State,
    dst: Reg,
    kind: MapLoadKind,
    _map_fd: i32,
) -> Vec<State> {
    // Modern LD_IMM64 subtypes are recognized by the decoder but not yet
    // supported by the transfer domain. Fail cleanly here.
    let feature = match kind {
        MapLoadKind::MapPtr | MapLoadKind::MapValue => None,
        // BPF_PSEUDO_FUNC is now handled below as PtrToCallback.
        MapLoadKind::PseudoFunc { .. } => None,
        // BPF_PSEUDO_BTF_ID: handled below for `__ksym` extern relocations
        // when a `RelocKind::Ksym` reloc is registered for the LDIMM64 PC.
        // Bare `PseudoBtfId` without a reloc still falls through to reject
        // (kernel BTF id without our resolution context — we don't ship
        // vmlinux BTF).
        MapLoadKind::PseudoBtfId { .. } => None,
        MapLoadKind::PseudoMapIdx => Some("LD_IMM64 BPF_PSEUDO_MAP_IDX"),
        MapLoadKind::PseudoMapIdxValue => Some("LD_IMM64 BPF_PSEUDO_MAP_IDX_VALUE"),
    };
    if let Some(feature) = feature {
        env.fail(VerificationError::UnsupportedModernFeature {
            pc: state.pc,
            feature,
        });
        return vec![];
    }

    // BPF_PSEUDO_FUNC: materialize a callback pointer. Target PC was
    // resolved at decode time; no relocation lookup is needed. Consumed
    // by bpf_loop / bpf_for_each_map_elem / bpf_timer_set_callback and
    // by bpf_set_exception_callback.
    if let MapLoadKind::PseudoFunc { subprog_pc } = kind {
        state.types.set(dst, RegType::PtrToCallback { subprog_pc });
        state.domain.forget(dst);
        state.pc += 2;
        return vec![state];
    }

    // BPF_PSEUDO_BTF_ID for `__ksym` externs. The kernel resolves these to
    // a kernel BTF id at load time; we don't ship vmlinux BTF, so we route
    // off the `RelocKind::Ksym` info (struct name + percpu flag from the
    // .o-file's `.ksyms` BTF DATASEC). Typed struct ksyms become
    // `PtrToBtfId{flags: TRUSTED|MEM_RDONLY[|PERCPU]}`; typeless / primitive
    // ksyms (`extern const int X __ksym;`, `extern const void X __ksym;`)
    // become a scalar address — code that uses them as `(__u64)&X` is fine
    // either way; passing them to `bpf_per_cpu_ptr` requires the typed form.
    if matches!(kind, MapLoadKind::PseudoBtfId { .. }) {
        if let Some(reloc) = env.ctx.pc_to_reloc.get(&state.pc).cloned() {
            if reloc.kind == crate::parsing::elf::RelocKind::Ksym {
                use crate::analysis::machine::context::intern_btf_type_name_strict;
                use crate::analysis::machine::reg_types::PtrFlags;
                let mut flags = PtrFlags::TRUSTED | PtrFlags::RDONLY;
                if reloc.ksym_is_percpu {
                    flags |= PtrFlags::PERCPU;
                }
                // Typed struct ksyms get the resolved struct name.
                // Primitive / typeless ksyms (`extern const int X __ksym;`,
                // `extern const void X __ksym;`) become PtrToBtfId with
                // type_name="unknown" — the flag combination still routes
                // through `bpf_per_cpu_ptr`'s arg check (PERCPU-tagged
                // BTF id), and `(__u64)&X`-style scalar uses just take
                // the address through ptr-to-int conversion.
                let type_name = reloc
                    .ksym_struct_name
                    .as_deref()
                    .map(intern_btf_type_name_strict)
                    .unwrap_or("unknown");
                state.types.set(
                    dst,
                    RegType::PtrToBtfId {
                        type_name,
                        flags,
                        ref_id: None,
                    },
                );
                state.domain.forget(dst);
                state.pc += 2;
                return vec![state];
            }
        }
        // No reloc info / unrecognized form. Fall through to reject —
        // a bare PSEUDO_BTF_ID without a Ksym reloc means the symbol
        // wasn't in `.ksyms`, which we can't resolve.
        env.fail(VerificationError::UnsupportedModernFeature {
            pc: state.pc,
            feature: "LD_IMM64 BPF_PSEUDO_BTF_ID (ksym/percpu)",
        });
        return vec![];
    }

    let reloc_info = env.ctx.pc_to_reloc.get(&state.pc);
    if let Some(reloc) = reloc_info {
        let is_static_data = env
            .ctx
            .map_defs
            .get(reloc.map_idx)
            .map(|md| {
                let n = md.name.as_str();
                n == ".bss"
                    || n == ".data"
                    || n == ".rodata"
                    || n.starts_with(".bss.")
                    || n.starts_with(".data.")
                    || n.starts_with(".rodata.")
            })
            .unwrap_or(false);
        let reloc_offset = reloc.offset;
        crate::analysis::transfer::types::update_map_load_types(
            &mut state.types,
            kind,
            reloc.map_idx,
            dst,
            reloc_offset,
            is_static_data,
        );
        // Seed the interval map-value PtrOffset at the relocation offset
        // instead of forgetting the numeric domain. Without this, a direct
        // map-value load (PSEUDO_MAP_VALUE / .bss/.data/.rodata global) had
        // NO PtrOffset, so a bounded-variable index — e.g. `hits[cpu & 255]`
        // — lost its range and `interval_check_map_access` bailed to the
        // zone fallback, FALSE-REJECTing "Unsafe map load". Seeding keeps the
        // downstream `min_off >= 0 && max_off <= value_size` check intact
        // (it can only reject MORE, never accept OOB — FA-safe). Non-MapValue
        // kinds (PtrToMapObject) keep the plain forget.
        if matches!(state.types.get(dst), RegType::PtrToMapValue { .. }) {
            state.domain.init_map_value_ptr_at(dst, reloc_offset);
        } else {
            state.domain.forget(dst);
        }
        state.pc += 2;
        vec![state]
    } else {
        env.fail(VerificationError::RelocationInfoMissing { pc: state.pc });
        vec![]
    }
}
