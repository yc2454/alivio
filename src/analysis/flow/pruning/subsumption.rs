// src/analysis/flow/pruning/subsumption.rs
//
// Subsumption predicates: state_subsumed_by and all helpers.

use std::collections::HashSet;

use crate::analysis::machine::env::SubsumptionMissReason;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::{RegType, TypeState};
use crate::analysis::machine::state::State;
use crate::common::config::VerifierConfig;
use crate::domains::numeric::NumericDomain;
use crate::domains::tnum::Tnum;

fn callee_saved_regs() -> HashSet<Reg> {
    [Reg::R6, Reg::R7, Reg::R8, Reg::R9].into_iter().collect()
}

/// Mirror of kernel `states_maybe_looping` (verifier.c v6.15 L18884).
/// Topmost frame registers R0..R10 must be bytewise identical and the
/// call-stack depth must match. The kernel uses `memcmp` ignoring the
/// `parent` pointer; alivio compares the abstract fields that together
/// constitute the per-reg state at this site.
pub(super) fn states_maybe_looping(prev: &State, cur: &State) -> bool {
    if prev.frames.depth() != cur.frames.depth() {
        return false;
    }
    // Compare the "hard" semantic state: type, numeric value bounds, and
    // scalar-id linkage. tnum/precise_regs are intentionally EXCLUDED:
    // the kernel sets precision via mark_chain_precision (backward walk
    // that updates BOTH cached and current state), and refines tnum via
    // reg_set_min_max only on scalar registers — alivio eager-propagates
    // both forward, which makes cached vs current state diverge on
    // bookkeeping that the kernel keeps in lock-step. The faithful
    // signal for "this state is identical at this pc" is the abstract
    // value + type, which is what actually determines verifier progress.
    for r in Reg::ALL {
        if prev.types.get(r) != cur.types.get(r) {
            return false;
        }
        // scalar_ids intentionally NOT compared here. Kernel's
        // `states_maybe_looping` does `memcmp(prev_reg, cur_reg,
        // offsetof(frameno))` which compares the byte representation
        // of bpf_reg_state up to frameno; the `id` field gets compared
        // too in principle, but the kernel canonicalizes ids via
        // `check_ids` before this point so that semantically-equivalent
        // states have equal ids. alivio mints fresh `scalar_id` on every
        // memory load (e.g. `r3 = *(u8*)(r10-N)` each iteration),
        // producing per-iteration distinct ids for the same abstract
        // value. That's a alivio-internal bookkeeping artifact, not a
        // semantic difference. Comparing ids here would spuriously
        // suppress the infinite-loop trap (mov64sx_s32_varoff_1 family),
        // letting unsound programs through. Type + abstract value +
        // tnum capture the actual reg state for the trap.
        if prev.domain.get_interval(r) != cur.domain.get_interval(r) {
            return false;
        }
        if prev.domain.get_u32_bounds(r) != cur.domain.get_u32_bounds(r) {
            return false;
        }
        if prev.tnums.get(&r) != cur.tnums.get(&r) {
            return false;
        }
    }
    true
}

/// Mirror of kernel `iter_active_depths_differ` (verifier.c v6.15 L18965).
/// Walks all frames' stack slots; for each slot whose `prev` carries an
/// ACTIVE iterator, the matching slot in `cur` must have the same
/// `iter.depth`. A differing depth means the loop IS making progress and
/// the infinite-loop trap should NOT fire.
pub(super) fn iter_active_depths_differ(prev: &State, cur: &State) -> bool {
    use crate::analysis::machine::frame_stack::FrameLevel;
    use crate::analysis::machine::stack_state::IterState;

    let depth = prev.frames.depth().min(cur.frames.depth());
    for fi in 0..depth {
        let level = FrameLevel::from_index(fi);
        let prev_frame = prev.frames.get(level);
        let cur_frame = cur.frames.get(level);
        for off in prev_frame.stack.slot_offsets() {
            let Some(prev_slot) = prev_frame.stack.get_slot(off) else {
                continue;
            };
            let Some(prev_it) = prev_slot.iterator else {
                continue;
            };
            if prev_it.state != IterState::Active {
                continue;
            }
            // The matching slot in cur. If absent or no iter ⇒ treat as
            // different depth (the loop's iter context changed).
            let Some(cur_slot) = cur_frame.stack.get_slot(off) else {
                return true;
            };
            let Some(cur_it) = cur_slot.iterator else {
                return true;
            };
            if cur_it.depth != prev_it.depth {
                return true;
            }
        }
    }
    false
}

/// Mirror of kernel `states_equal(old, cur, EXACT)` (verifier.c v6.15
/// L18838-L18883). Strict equality used by the infinite-loop trap; ranges
/// must match exactly (no widening allowed). Compared field-by-field
/// against `prev`. Returns true iff every semantic field alivio tracks is
/// identical between `prev` and `cur`. Path-bookkeeping fields
/// (`history_idx`, `parent_cache_id`, `cache_id`, `children_unsafe`) and
/// the BCF symbolic state are intentionally excluded — they don't bear on
/// the kernel's notion of "same verifier state".
pub(super) fn state_exact_equal(prev: &State, cur: &State) -> bool {
    if !states_maybe_looping(prev, cur) {
        return false;
    }
    // Per-frame stack equality, plus caller register/domain/tnum snapshots
    // on non-top frames. `CallFrame: PartialEq` covers this.
    use crate::analysis::machine::frame_stack::FrameLevel;
    if prev.frames.depth() != cur.frames.depth() {
        return false;
    }
    for fi in 0..prev.frames.depth() {
        let level = FrameLevel::from_index(fi);
        if prev.frames.get(level) != cur.frames.get(level) {
            return false;
        }
    }
    // Lock / ref / preempt / rcu / irq state — every per-path semantic field.
    if prev.active_refs != cur.active_refs
        || prev.active_lock != cur.active_lock
        || prev.rcu_read_depth != cur.rcu_read_depth
        || prev.implicit_rcu_at_entry != cur.implicit_rcu_at_entry
        || prev.active_preempt_locks != cur.active_preempt_locks
        || prev.acquired_irq_ids != cur.acquired_irq_ids
        || prev.acquired_res_locks != cur.acquired_res_locks
        || prev.goto_budget != cur.goto_budget
        || prev.var_off_contributor != cur.var_off_contributor
        || prev.ptr_const_off != cur.ptr_const_off
        || prev.btf_field_refs != cur.btf_field_refs
        || prev.kernel_tnum_imprecise != cur.kernel_tnum_imprecise
    {
        return false;
    }
    true
}

/// Check if `cur` is subsumed by `old` (old covers all behaviors of cur).
/// Returns `Ok(())` on success or `Err(reason)` identifying the *first*
/// sub-check that rejected.
pub(super) fn state_subsumed_by(
    cur: &State,
    old: &State,
    live_regs: &HashSet<Reg>,
    frame_live_slots: &[Option<HashSet<i16>>],
    // Per-frame live mask for the caller-frame compare (kernel
    // states_equal: `insn_idx = frame_insn_idx(old, i)` — the frame's
    // CALLSITE insn for non-top frames — then func_states_equal masks
    // every reg by `insn_aux_data[insn_idx].live_regs_before`,
    // verifier.c:20069-20085/:20131-20137). Index k = the mask for
    // frames[k].caller_types (saved at frames[k]'s callsite =
    // return_pc - 1). `None` = mask unknown → fall back to the legacy
    // r6-r9 set (the sound, stricter direction).
    frame_live_regs: &[Option<HashSet<Reg>>],
    config: &VerifierConfig,
    force_exact: bool,
) -> Result<(), SubsumptionMissReason> {
    // Order matters for instrumentation: the *first* rejecting check
    // is what the returned miss reason names, so cheaper / more-
    // fundamental checks come first.
    if !types_subsumed_by(&cur.types, &old.types, live_regs) {
        // Measurement hatch (ALIVIO_DUMP_SUBSUM_MISS): on a Types
        // miss, re-scan to report the first offending live reg + its
        // (cur, old) RegType at this pc. Runs ONLY when the env var is
        // set AND we already know the check failed — zero hot-path /
        // behavioral effect otherwise. Used to localize the
        // clean_verifier_state / liveness-fidelity gap (skb_drop = 100%
        // types misses).
        if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
            for &r in live_regs {
                let ct = cur.types.get(r);
                let ot = old.types.get(r);
                if !type_subsumed_by(&ct, &ot) {
                    eprintln!(
                        "[types_miss] pc={} reg={:?} cur={:?} old={:?}",
                        cur.pc, r, ct, ot
                    );
                    break;
                }
            }
        }
        return Err(SubsumptionMissReason::Types);
    }
    if !config.skip_dbm_check
        && !domain_subsumed_by(
            &cur.domain,
            &old.domain,
            &cur.types,
            &old.types,
            live_regs,
            &old.precise_regs,
            force_exact,
        )
    {
        return Err(SubsumptionMissReason::Domain);
    }
    if !stack_subsumed_by(cur, old, frame_live_slots, force_exact) {
        return Err(SubsumptionMissReason::Stack);
    }
    if !tnum_subsumed_by(cur, old, live_regs) {
        return Err(SubsumptionMissReason::Tnum);
    }

    // regsafe scalar-id check.
    // If two live registers share a scalar_id in `old` (so a future
    // refinement on one will propagate to the other along the cached
    // continuation), `cur` must also have them linked. Otherwise the
    // cur-state's continuation would refine them independently — pruning
    // it against `old` hides paths where the unlinked register stays
    // unbounded. Mirrors upstream `check_ids` in `regsafe`.
    // Scalar ids: kernel-faithful single bijective idmap, precision-
    // gated (regsafe SCALAR). Pointer/packet linkage: the existing
    // pairwise relation (separate, unchanged). Both attribute to the
    // ScalarIdLinks miss bucket.
    if !scalar_ids_subsumed_by(cur, old, live_regs) {
        return Err(SubsumptionMissReason::ScalarIdLinks);
    }
    if !scalar_id_links_subsumed_by(cur, old, live_regs) {
        return Err(SubsumptionMissReason::ScalarIdLinks);
    }

    // Active-lock identity. When `old.active_lock` names a specific
    // map_value (`ptr_id`), every live register that *currently* holds
    // that map_value in `old` must still hold the same map_value in
    // `cur` — otherwise a future `bpf_spin_unlock` along the cached
    // continuation through such a register would mismatch the lock in
    // `cur`. This caught the FALSE_ACCEPT in
    // `verifier_spin_lock::reg_id_for_map_value`, where one path
    // reassigns the lock-holding register to a different map_value.
    if !active_lock_subsumed_by(cur, old, live_regs) {
        return Err(SubsumptionMissReason::ActiveLock);
    }

    // Active synchronization depth (RCU read-side / preempt-disable / IRQ).
    // These are part of the kernel verifier state and `states_equal`
    // compares them exactly. They are NOT range-narrowable: a `cur` that
    // holds an open RCU read section (or preempt/IRQ) which `old` does not
    // carries an unreleased-section exit obligation (kernel rejects an exit
    // with a non-baseline rcu_read_depth) AND a different set of
    // allowed helpers along its continuation, neither of which `old`'s
    // continuation checked. Pruning it drops the held-section exit path and
    // FALSE-ACCEPTs (rcu_read_lock::non_sleepable_rcu_mismatch — same shape
    // as the spin-lock case). Require exact equality.
    if old.rcu_read_depth != cur.rcu_read_depth
        || old.implicit_rcu_at_entry != cur.implicit_rcu_at_entry
        || old.active_preempt_locks != cur.active_preempt_locks
        || old.acquired_irq_ids != cur.acquired_irq_ids
    {
        return Err(SubsumptionMissReason::ActiveLock);
    }

    // `old` must have at least as much may_goto budget remaining as
    // `cur`, otherwise pruning would let `cur` continue under behaviours
    // `old` never explored (old already exhausted the budget on a path cur
    // hasn't yet reached). Monotone: budget only ever decreases, so once
    // cur's future iterations are covered by an old state with a larger or
    // equal counter, pruning is sound.
    if old.goto_budget < cur.goto_budget {
        return Err(SubsumptionMissReason::GotoBudget);
    }

    // Active refcount-tracked acquisitions (dynptr / sock / cpumask /
    // kptr / ...) must be a subset in `cur` of those held by `old`. If
    // `cur` carries an active ref that `old` doesn't, pruning would
    // hide a leak: the cached continuation from `old` already proved
    // there's no leaking exit, but along that continuation cur's extra
    // ref never gets released — exit leak-check would catch it on cur
    // but not on old. Caught `dynptr_fail::ringbuf_missing_release2`,
    // where one branch releases both ptr1+ptr2 and the other only ptr1.
    if !cur.active_refs.is_subset(&old.active_refs) {
        return Err(SubsumptionMissReason::ActiveRefs);
    }

    // Check caller frames: callee-saved registers (r6-r9) persist across
    // calls and determine post-return control flow. Without this check,
    // two states that differ only in caller-frame r6-r9 values get pruned
    // against each other, hiding bugs that manifest after return.
    let saved = callee_saved_regs();
    for (k, (cur_frame, old_frame)) in cur.frames.iter().zip(old.frames.iter()).enumerate() {
        // Kernel func_states_equal masks the frame's regs by the static
        // live set at the frame's own insn (callsite for caller frames,
        // verifier.c:20081 `(1 << i) & live_regs`). A callee-saved reg
        // that is DEAD after this callsite's return must not block the
        // hit; one that IS live after return is compared.
        // The compare mask is live_regs_before[callsite]
        // (func_states_equal, :20081), but the kernel's
        // clean_verifier_state has ALREADY marked dead regs in completed
        // cached states NOT_INIT via DYNAMIC read marks — and a caller
        // frame's r0-r5 can never be read after a state inside the
        // callee (they are scratched at return; the callee reads its OWN
        // r1-r5 copies), so cached caller-frame args are always cleaned
        // and never block (regsafe: rold NOT_INIT → safe). The static
        // equivalent: intersect the callsite live set with the
        // callee-saved regs.
        let masked: HashSet<Reg>;
        let mask: &HashSet<Reg> = match frame_live_regs.get(k).and_then(|m| m.as_ref()) {
            Some(live) => {
                masked = live.intersection(&saved).copied().collect();
                &masked
            }
            None => &saved,
        };
        if !types_subsumed_by(&cur_frame.caller_types, &old_frame.caller_types, mask) {
            return Err(SubsumptionMissReason::CallerFrame);
        }
        if !config.skip_dbm_check
            && !domain_subsumed_by(
                &cur_frame.caller_domain,
                &old_frame.caller_domain,
                &cur_frame.caller_types,
                &old_frame.caller_types,
                mask,
                &HashSet::new(),
                false,
            )
        {
            return Err(SubsumptionMissReason::CallerFrame);
        }
        if !caller_tnum_subsumed_by(cur_frame, old_frame, mask) {
            return Err(SubsumptionMissReason::CallerFrame);
        }
    }

    Ok(())
}

/// Linkage class for a register, used by `scalar_id_links_subsumed_by`.
///
/// Two registers belong to the same equivalence class when a future
/// refinement (e.g. null-check, range narrowing) on one will propagate
/// to the other along the kernel verifier's id-tracking. This covers:
///   - scalars sharing a `scalar_id`
///   - id-bearing nullable pointer types (`PtrToMapValueOrNull`,
///     `PtrToBtfIdOrNull`, `PtrToAllocMemOrNull`) sharing an id — null
///     refinement promotes all class members to the non-null form.
///   - the non-null forms `PtrToMapValue { id, .. }`, `PtrToAllocMem { id, .. }`
///     — the id persists post-refinement and still drives propagation.
///
/// The numeric tag in `LinkageKind` keeps classes from different RegType
/// variants disjoint even when their ids collide as `u32` values.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
enum LinkageKind {
    Scalar,
    MapValue,
    MapValueOrNull,
    BtfIdOrNull,
    AllocMem,
    AllocMemOrNull,
    /// Interval-mode packet-pointer family (kernel `reg->id`).
    /// Two registers with the same `(PacketPtr, id)` share a variable
    /// offset chain; a bounds check on one refines `range` for all.
    /// Zone mode handles this via DBM cells, not ids — the
    /// corresponding subsumption check lives in `zone_subsumed_by`.
    PacketPtr,
}

fn linkage_key(state: &State, r: Reg) -> Option<(LinkageKind, u32)> {
    match state.types.get(r) {
        RegType::PtrToMapValueOrNull { id, .. } => Some((LinkageKind::MapValueOrNull, id)),
        RegType::PtrToMapValue { id, .. } => Some((LinkageKind::MapValue, id)),
        RegType::PtrToBtfIdOrNull { id, .. } => Some((LinkageKind::BtfIdOrNull, id)),
        RegType::PtrToAllocMemOrNull { id, .. } => Some((LinkageKind::AllocMemOrNull, id)),
        RegType::PtrToAllocMem { id, .. } => Some((LinkageKind::AllocMem, id)),
        RegType::ScalarValue => state.scalar_id(r).map(|id| (LinkageKind::Scalar, id)),
        RegType::PtrToPacket | RegType::PtrToPacketEnd | RegType::PtrToPacketMeta => {
            if let NumericDomain::Interval(ref ivl) = state.domain {
                ivl.get_ptr_offset(r)
                    .and_then(|po| po.id)
                    .map(|id| (LinkageKind::PacketPtr, id))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// `old.active_lock` constraint check: for every live register that
/// holds the locked map_value in `old` (i.e. its `PtrToMapValue.id`
/// equals `old.active_lock.ptr_id`), the same register in `cur` must
/// still hold a map_value whose id equals `cur.active_lock.ptr_id`.
///
/// Encodes the rule that pruning must not collapse a state where the
/// lock's owning register has been reassigned to a different map_value
/// — `bpf_spin_unlock` later in the cached continuation would target
/// the wrong identity. See `verifier_spin_lock::reg_id_for_map_value`.
fn active_lock_subsumed_by(cur: &State, old: &State, live_regs: &HashSet<Reg>) -> bool {
    let Some(old_lock) = old.get_active_lock() else {
        // `old` holds no lock. It can only subsume `cur` if `cur` also
        // holds no lock: a lock-held `cur` carries an unreleased-lock exit
        // obligation (kernel "BPF_EXIT ... inside bpf_spin_lock-ed region")
        // that the no-lock `old`'s continuation never checked. Pruning it
        // here drops the lock-held exit path and FALSE-ACCEPTs
        // (verifier_spin_lock::spin_lock_test6_missing_unlock). Mirrors the
        // kernel `states_equal` lock-state comparison.
        return cur.get_active_lock().is_none();
    };
    let cur_lock_ptr = cur.get_active_lock().map(|l| l.ptr_id);
    for &r in live_regs {
        if let RegType::PtrToMapValue { id: old_id, .. } = old.types.get(r) {
            if old_id != old_lock.ptr_id {
                continue;
            }
            // r holds the lock's map_value in `old`. Require the same
            // in `cur`: cur.r must be a PtrToMapValue whose id matches
            // cur's active_lock.
            let RegType::PtrToMapValue { id: cur_id, .. } = cur.types.get(r) else {
                return false;
            };
            if Some(cur_id) != cur_lock_ptr {
                return false;
            }
        }
    }
    true
}

/// Kernel `check_ids` (verifier.c:19383): a per-comparison consistent
/// bijection `old_id ↔ cur_id`. Both zero ⇒ ok; exactly one zero ⇒
/// mismatch; else old_id must map to exactly one cur_id and a cur_id
/// may be claimed by only one old_id. `map` holds the recorded pairs
/// (alivio live-reg count is tiny, so the linear scan is trivial vs the
/// kernel's fixed BPF_ID_MAP_SIZE array).
fn check_ids(old_id: u32, cur_id: u32, map: &mut Vec<(u32, u32)>) -> bool {
    if (old_id != 0) != (cur_id != 0) {
        return false;
    }
    if old_id == 0 {
        return true;
    }
    for &(o, c) in map.iter() {
        if o == old_id {
            return c == cur_id;
        }
        if c == cur_id {
            return false;
        }
    }
    map.push((old_id, cur_id));
    true
}

/// Kernel `check_scalar_ids` (verifier.c:19416): like `check_ids` but a
/// zero id gets a fresh unique temp so `0 vs ID` / `ID vs 0` are valid
/// (but still consistently bijective). `tmp` is a per-comparison
/// generator seeded high (disjoint from real low-valued alivio ids).
fn check_scalar_ids(old_id: u32, cur_id: u32, map: &mut Vec<(u32, u32)>, tmp: &mut u32) -> bool {
    let o = if old_id != 0 {
        old_id
    } else {
        *tmp -= 1;
        *tmp
    };
    let c = if cur_id != 0 {
        cur_id
    } else {
        *tmp -= 1;
        *tmp
    };
    check_ids(o, c, map)
}

/// Kernel-faithful scalar-id check (regsafe SCALAR, verifier.c:19560):
/// scalar id is compared ONLY for a *precise* old scalar — an imprecise
/// old scalar is a wildcard (`if (!rold->precise && exact==NOT_EXACT)
/// return true`), so its id is never checked. All precise live scalars
/// are run through ONE bijective `check_scalar_ids` map, exactly as the
/// kernel threads `env->idmap_scratch` through every `regsafe`. This
/// replaces the scalar half of the old piecemeal pairwise
/// `scalar_id_links_subsumed_by` (pointer/packet linkage stays there):
/// the single bijection preserves linkage (same old id ⇒ same cur id)
/// AND is more permissive than exact-equality (remappable), while the
/// precision gate drops the over-conservative imprecise-scalar links
/// the kernel never checks.
fn scalar_ids_subsumed_by(cur: &State, old: &State, live_regs: &HashSet<Reg>) -> bool {
    let mut map: Vec<(u32, u32)> = Vec::new();
    let mut tmp: u32 = u32::MAX;
    for &r in live_regs {
        if old.types.get(r) != RegType::ScalarValue {
            continue;
        }
        if !old.is_reg_precise(r) {
            continue; // imprecise old scalar = wildcard (kernel)
        }
        // Kernel regsafe `BPF_ADD_CONST` (verifier.c v6.15 L19732): the
        // add-const FLAG must match between old and cur, and when set, the
        // delta OFF must match too. This is what keeps a loop's first
        // iteration (base reg, no add-const) distinct from later iterations
        // (the `rX = rY; rX += K` link, off=K) so the access bounds are
        // re-verified — `verifier_iterating_callbacks::check_add_const`.
        // Subsumption-STRICTENING ⇒ more exploration ⇒ FA-safe; inert in
        // BCF mode (scalar_id_off is empty there, so both sides are None).
        let o_off = old.scalar_id_off(r);
        let c_off = cur.scalar_id_off(r);
        if o_off.is_some() != c_off.is_some() {
            return false; // add-const flag mismatch
        }
        if o_off.is_some() && o_off != c_off {
            return false; // off mismatch while flag set
        }
        let oid = old.scalar_id(r).unwrap_or(0);
        let cid = cur.scalar_id(r).unwrap_or(0);
        if !check_scalar_ids(oid, cid, &mut map, &mut tmp) {
            return false;
        }
    }
    true
}

/// Conservative id-equivalence check used by `state_subsumed_by`.
///
/// Returns true iff every pair `(r1, r2)` of live regs in the same
/// linkage class in `old` is also in the same linkage class in `cur`.
/// This is the safe direction: `cur` may have MORE links than `old`
/// (refinement narrows), but `old` cannot have links that `cur` lacks —
/// those are exactly the cases where future refinement in old's
/// continuation would silently miss propagation in cur. Mirrors
/// upstream `check_ids` in `regsafe`.
fn scalar_id_links_subsumed_by(cur: &State, old: &State, live_regs: &HashSet<Reg>) -> bool {
    let live: Vec<Reg> = live_regs.iter().copied().collect();
    for i in 0..live.len() {
        for j in (i + 1)..live.len() {
            let r1 = live[i];
            let r2 = live[j];
            // Scalar linkage now goes through the kernel-faithful
            // bijective `scalar_ids_subsumed_by`; this pairwise check
            // covers ONLY the pointer/packet linkage kinds.
            let old_link = matches!(
                (linkage_key(old, r1), linkage_key(old, r2)),
                (Some(a), Some(b)) if a == b && a.0 != LinkageKind::Scalar
            );
            if !old_link {
                continue;
            }
            let cur_link = matches!(
                (linkage_key(cur, r1), linkage_key(cur, r2)),
                (Some(a), Some(b)) if a == b && a.0 != LinkageKind::Scalar
            );
            if !cur_link {
                return false;
            }
        }
    }
    true
}

fn types_subsumed_by(cur: &TypeState, old: &TypeState, live_regs: &HashSet<Reg>) -> bool {
    for &r in live_regs {
        if !type_subsumed_by(&cur.get(r), &old.get(r)) {
            // ALIVIO_DUMP_SUBSUM_MISS=1: name the live reg + type pair that
            // blocks the Types verdict.
            if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                eprintln!(
                    "[types_miss] reg={:?} old={:?} cur={:?}",
                    r,
                    old.get(r),
                    cur.get(r)
                );
            }
            return false;
        }
    }
    true
}

fn type_subsumed_by(cur_ty: &RegType, old_ty: &RegType) -> bool {
    use RegType::*;

    match (old_ty, cur_ty) {
        // Identical types
        (ScalarValue, ScalarValue) => true,
        (NotInit, NotInit) => true,
        (PtrToCtx, PtrToCtx) => true,
        (PtrToPacketEnd, PtrToPacketEnd) => true,

        // Anything subsumes NotInit
        (NotInit, _) => true,

        // Packet pointers: old must have >= range
        (PtrToPacket, PtrToPacket) => true,

        // Map value pointers
        (
            PtrToMapValue {
                offset: o1,
                map_idx: m1,
                ..
            },
            PtrToMapValue {
                offset: o2,
                map_idx: m2,
                ..
            },
        ) => {
            m1 == m2
                && match (o1, o2) {
                    (None, _) => true,
                    (Some(a), Some(b)) => a == b,
                    (Some(_), None) => false,
                }
        }

        // Map value or null. Like `PtrToAllocMem` below, the kernel
        // mints a fresh `id` on every `bpf_map_lookup_elem` call —
        // looping `map_val = bpf_map_lookup_elem(...); if (map_val) ...`
        // produces non-equal-but-semantically-identical pointers across
        // iterations and id-equality blocks loop-top subsumption.
        // Structural identity is `map_idx` (which map); `id` is a per-
        // call tag used for null-check narrowing on the *current*
        // state's continuation, not for cross-state subsumption.
        // Pattern observed in iters.c::iter_tricky_but_fine.
        (PtrToMapValueOrNull { map_idx: m1, .. }, PtrToMapValueOrNull { map_idx: m2, .. }) => {
            m1 == m2
        }

        // Socket pointers
        (PtrToSocket { ref_id: id1 }, PtrToSocket { ref_id: id2 }) => id1 == id2,
        (PtrToSocketOrNull { ref_id: id1 }, PtrToSocketOrNull { ref_id: id2 }) => id1 == id2,

        // Stack pointers - DBM subsumption covers the numeric relationship
        (PtrToStack { frame_level: fl1 }, PtrToStack { frame_level: fl2 }) => fl1 == fl2,

        // PtrToAllocMem from `bpf_iter_*_next` etc.: the dispatcher mints
        // a fresh `id` on every call, so two visits to the same loop top
        // hold non-equal-but-semantically-identical allocs in the loop
        // variable. Subsume when (mem_size, ref_id) match — `ref_id`
        // None means unref-tracked iter-elem alloc, Some(N) means the
        // alloc is owned by a tracked acquire (dynptr_data slice from
        // a specific dynptr; ringbuf reservation). For the latter, the
        // matching ref_id ensures we don't conflate two acquires;
        // mem_size pins the bounds-check budget. Without this rule,
        // unbounded `bpf_for_each` loops state-explode (each iter's
        // fresh id breaks loop-top subsumption on the loop variable).
        // The `id` field is intentionally ignored — it's a per-call
        // tag, not a structural property.
        (
            PtrToAllocMem {
                mem_size: ms1,
                ref_id: ri1,
                ..
            },
            PtrToAllocMem {
                mem_size: ms2,
                ref_id: ri2,
                ..
            },
        ) => ms1 == ms2 && ri1 == ri2,
        (
            PtrToAllocMemOrNull {
                mem_size: ms1,
                ref_id: ri1,
                ..
            },
            PtrToAllocMemOrNull {
                mem_size: ms2,
                ref_id: ri2,
                ..
            },
        ) => ms1 == ms2 && ri1 == ri2,

        // Default: structural equality. Covers variants without a
        // looser explicit rule (PtrToBtfId, PtrToCpumask, PtrToArena,
        // PtrToCgroup, PtrToTask, PtrToOwnedKptr, PtrToMapKptr,
        // PtrToCallback, PtrToSockCommon, PtrToTcpSock, PtrToPacketMeta,
        // and the *OrNull versions of the above). Without this fallback,
        // identical pointer types compare unequal at prune-points and
        // every state is treated as novel — that's the entire reason
        // `bpf_cubic_cong_avoid` (and any struct_ops program with a
        // long-lived `PtrToBtfId` arg in r6-r9) hits the complexity
        // limit. PartialEq is derived on RegType, so structural ==
        // is the right canonical check for these.
        (a, b) if a == b => true,
        _ => false,
    }
}

fn domain_subsumed_by(
    cur: &NumericDomain,
    old: &NumericDomain,
    cur_types: &TypeState,
    old_types: &TypeState,
    live_regs: &HashSet<Reg>,
    precise: &HashSet<Reg>,
    force_exact: bool,
) -> bool {
    // Kernel `regsafe` rule (verifier.c v6.15 L18357 / L18387):
    //   - precise → range_within (old ⊇ cur)
    //   - !precise → accept under NOT_EXACT (kernel doesn't compare
    //     imprecise scalars across cur/old at all).
    //   - !precise under RANGE_WITHIN (force_exact=true, we're inside
    //     an open SCC): kernel still checks range_within — the SCC's
    //     soundness depends on each iteration's state being covered,
    //     even for non-precise regs (verifier.c L18313 — the early-
    //     return on `!rold->precise && exact == NOT_EXACT` doesn't
    //     fire when exact != NOT_EXACT). This is the gate that fixes
    //     iters.c::loop_state_deps2: visit-2 with `r6=1` doesn't get
    //     subsumed by visit-1's `r6=0` once the inner-iter SCC is
    //     still open.
    for &r in live_regs {
        if !precise.contains(&r) && !force_exact {
            continue;
        }
        // ⚠️ LOOSER than the kernel: skip the scalar-interval
        // range_within for pointer-typed regs. `regsafe` (verifier.c
        // v6.15 L19769-19811) DOES apply `range_within` to
        // PTR_TO_MAP_VALUE/PACKET/MEM/BUF and the stricter `regs_exact`
        // to PTR_TO_CTX/sockets/stack. types_subsumed_by (runs first) +
        // tnum + DBM/interval_subsumed_by still constrain the pointer.
        if cur_types.get(r).is_pointer() || old_types.get(r).is_pointer() {
            continue;
        }
        // Kernel `range_within` (verifier.c v6.15 L19360): all 8
        // dimensions of cur must be contained in old's. Tighter than
        // checking only signed 64-bit. The 32-bit halves help when
        // upstream transfers tracked them precisely
        // (sync_bounds-aware ops like apply_add); for ops that haven't
        // been wired yet, the 32-bit halves stay at full range and
        // the corresponding dim is automatically vacuous (old is
        // full ⇒ contains anything).
        let (old_smin, old_smax) = old.get_interval(r);
        let (cur_smin, cur_smax) = cur.get_interval(r);
        if !(old_smin <= cur_smin && old_smax >= cur_smax) {
            if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                eprintln!(
                    "[domain_miss] reg={:?} precise={} force_exact={} s64 old=[{},{}] cur=[{},{}]",
                    r,
                    precise.contains(&r),
                    force_exact,
                    old_smin,
                    old_smax,
                    cur_smin,
                    cur_smax
                );
            }
            return false;
        }
        // The 64-bit unsigned + 32-bit halves are only meaningful in
        // interval mode (Zone mode's bounds live elsewhere). Skip
        // the extra checks for Zone mode to preserve its existing
        // behavior — the 8-bound probe is interval-mode-only.
        if let (NumericDomain::Interval(old_ivl), NumericDomain::Interval(cur_ivl)) = (old, cur) {
            let ob = old_ivl.get_bounds(r);
            let cb = cur_ivl.get_bounds(r);
            if !(ob.umin <= cb.umin && ob.umax >= cb.umax) {
                if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                    eprintln!(
                        "[domain_miss] reg={:?} precise u64 old=[{},{}] cur=[{},{}]",
                        r, ob.umin, ob.umax, cb.umin, cb.umax
                    );
                }
                return false;
            }
            if !(ob.s32_min <= cb.s32_min && ob.s32_max >= cb.s32_max) {
                if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                    eprintln!(
                        "[domain_miss] reg={:?} precise s32 old=[{},{}] cur=[{},{}]",
                        r, ob.s32_min, ob.s32_max, cb.s32_min, cb.s32_max
                    );
                }
                return false;
            }
            if !(ob.u32_min <= cb.u32_min && ob.u32_max >= cb.u32_max) {
                if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                    eprintln!(
                        "[domain_miss] reg={:?} precise u32 old=[{},{}] cur=[{},{}]",
                        r, ob.u32_min, ob.u32_max, cb.u32_min, cb.u32_max
                    );
                }
                return false;
            }
        }
    }

    // Anchor-to-anchor constraints (packet bounds) must also be subsumed.
    // These represent relationships like data_end - data >= N that are
    // critical for packet access safety and persist across calls.
    match (old, cur) {
        (NumericDomain::Zone(old_dbm), NumericDomain::Zone(cur_dbm)) => {
            zone_subsumed_by(old_dbm, cur_dbm, live_regs)
        }
        (NumericDomain::Interval(old_ivl), NumericDomain::Interval(cur_ivl)) => {
            interval_subsumed_by(old_ivl, cur_ivl, live_regs)
        }
        _ => {
            // Mismatched domain types - should not happen in normal operation
            true
        }
    }
}

fn zone_subsumed_by(
    old_dbm: &crate::analysis::Dbm,
    cur_dbm: &crate::analysis::Dbm,
    live_regs: &HashSet<Reg>,
) -> bool {
    let anchors = [Reg::AnchorData, Reg::AnchorDataEnd, Reg::AnchorDataMeta];

    // Anchor↔anchor: packet-region geometry (e.g. `data_end - data >= N`).
    for &a in &anchors {
        for &b in &anchors {
            if a == b {
                continue;
            }
            if old_dbm.get(a, b) < cur_dbm.get(a, b) {
                if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                    eprintln!("[domain_miss] anchor-anchor a={:?} b={:?}", a, b);
                }
                return false;
            }
        }
    }

    // Live-reg pairs (including reg ↔ anchor): zone-mode analogue of
    // the kernel's id-tracking for packet pointers. Without this,
    // pruning collapses two states whose live registers differ in
    // their *relation* to one another or to a packet anchor —
    // e.g. one path established `r2 - r3 == 0` (`r2 = r3` aliasing)
    // and the other did not, but their standalone intervals coincide.
    // That's the FALSE_ACCEPT in
    // `verifier_direct_packet_access::id_in_regsafe_bad_access`.
    //
    // For subsumption: `old` covers `cur` only if every directed cell
    // `old.get(a, b) >= cur.get(a, b)` for live-reg pairs. (`>=` is
    // the looser direction in difference-bound semantics — a larger
    // upper bound on `a - b` is more permissive.)
    let live: Vec<Reg> = live_regs
        .iter()
        .copied()
        .filter(|r| !r.is_anchor())
        .collect();
    for &r in &live {
        for &a in &anchors {
            if old_dbm.get(r, a) < cur_dbm.get(r, a) {
                if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                    eprintln!("[domain_miss] reg-anchor r={:?} a={:?}", r, a);
                }
                return false;
            }
            if old_dbm.get(a, r) < cur_dbm.get(a, r) {
                if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                    eprintln!("[domain_miss] anchor-reg a={:?} r={:?}", a, r);
                }
                return false;
            }
        }
    }
    for i in 0..live.len() {
        for j in 0..live.len() {
            if i == j {
                continue;
            }
            let a = live[i];
            let b = live[j];
            if old_dbm.get(a, b) < cur_dbm.get(a, b) {
                return false;
            }
        }
    }
    true
}

fn interval_subsumed_by(
    old_ivl: &crate::domains::interval::IntervalState,
    cur_ivl: &crate::domains::interval::IntervalState,
    live_regs: &HashSet<Reg>,
) -> bool {
    // Interval domain: check packet_size_lower_bound and meta_size_lower_bound
    // For subsumption, old must be MORE permissive (fewer constraints) than cur.
    // If old requires a minimum packet size but cur doesn't, old does NOT subsume cur.
    let old_pkt = old_ivl.get_packet_size_bound().unwrap_or(0);
    let cur_pkt = cur_ivl.get_packet_size_bound().unwrap_or(0);
    if old_pkt > cur_pkt {
        if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
            eprintln!("[ivl_miss] pkt_bound old={} cur={}", old_pkt, cur_pkt);
        }
        return false;
    }
    let old_meta = old_ivl.get_meta_size_bound().unwrap_or(0);
    let cur_meta = cur_ivl.get_meta_size_bound().unwrap_or(0);
    if old_meta > cur_meta {
        return false;
    }

    // Per-register packet-pointer `range` subsumption — the register-level
    // analog of the stack-slot check in `stack_subsumed_by` (PtrToPacket /
    // PtrToPacketMeta `range`). The kernel's `regsafe` compares `reg->range`
    // for packet pointers: a cached state proving a register can access
    // `range` bytes does NOT subsume a current state with a smaller/absent
    // range, because the current path may reach a packet access that the
    // cached path would have rejected. Without this, the FALSE branch of a
    // bounds check (range=Some(N)) gets recorded first, then the TRUE branch
    // (range=None) is wrongly pruned against it and its unsafe access is
    // never verified — a soundness FALSE_ACCEPT
    // (verifier_xdp_direct_packet_access::pkt_*_bad_access_2_*).
    for r in Reg::ALL {
        // Kernel func_states_equal (verifier.c:19953): DEAD registers are
        // never compared — `((1 << i) & live_regs_before) && !regsafe(...)`,
        // unconditionally at every exact level. An ungated Reg::ALL loop
        // would compare packet ranges on dead regs and miss where the
        // kernel HITs. MAY-live over-approx ⇒ complement is MUST-dead ⇒
        // skipping is sound.
        if !live_regs.contains(&r) {
            continue;
        }
        let old_po = old_ivl.get_ptr_offset(r);
        let cur_po = cur_ivl.get_ptr_offset(r);

        // Prior good-range rule, preserved EXACTLY (Some/None distinction):
        // old proving a (≥0) range that cur lacks/under-proves blocks
        // subsumption. Untouched so BCF-mode behavior — where pkt_end_rel is
        // always None (gated off, see refine_data_region_bounds) — is
        // byte-identical to HEAD.
        let old_range = old_po.and_then(|po| po.range);
        let cur_range = cur_po.and_then(|po| po.range);
        match (old_range, cur_range) {
            (Some(_), None) => {
                if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                    eprintln!("[ivl_miss] reg={:?} range old=Some cur=None", r);
                }
                return false;
            }
            (Some(old_r), Some(cur_r)) if old_r > cur_r => {
                if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                    eprintln!("[ivl_miss] reg={:?} range old={} cur={}", r, old_r, cur_r);
                }
                return false;
            }
            _ => {}
        }

        // mark_pkt_end sentinels (base-mode only). Fold the BEYOND/AT
        // `reg->range` sentinels into the kernel `regsafe` rule
        // `rold->range > rcur->range → return false` (verifier.c L19801):
        // a `cur` marked out-of-range carries a resolved-dup-check fact an
        // unmarked `old` didn't establish, so old must not subsume it. With
        // pkt_end_rel == None on both (always so in BCF mode) the kernel_range
        // collapses to range.unwrap_or(0) and this never adds a block beyond
        // the rule above.
        let old_kr = old_po.map(|po| po.kernel_range()).unwrap_or(0);
        let cur_kr = cur_po.map(|po| po.kernel_range()).unwrap_or(0);
        if old_kr > cur_kr {
            return false;
        }
    }
    true
}

/// Stack-slot type subsumption: stricter than `type_subsumed_by`.
/// NotInit only subsumes NotInit (no "covers anything" rule), and
/// otherwise we use the same family rules as registers.
fn stack_slot_type_subsumed_by(new_ty: &RegType, old_ty: &RegType) -> bool {
    use RegType::*;
    match (old_ty, new_ty) {
        (NotInit, NotInit) => true,
        // For non-NotInit pairs, defer to register-style rules.
        // The default rule `(a, b) if a == b => true` covers most
        // pointer types; ScalarValue→ScalarValue covers the common
        // "spilled scalar" case; PtrToMapValue offsets etc. have
        // their own match arms in `type_subsumed_by`.
        _ => type_subsumed_by(new_ty, old_ty),
    }
}

fn stack_subsumed_by(
    cur: &State,
    old: &State,
    frame_live_slots: &[Option<HashSet<i16>>],
    force_exact: bool,
) -> bool {
    // clean_verifier_state analog (kernel clean_func_state,
    // verifier.c:19424): a stack slot the kernel proves dead is set to
    // STACK_INVALID so `stacksafe` skips it — only LIVE slots are ever
    // compared. Comparing the union of all slot offsets with NO liveness
    // filter would let a dead scratch slot differing across states block
    // every prune.
    // The kernel cleans EVERY frame at its own ip; `frame_live_slots[i]`
    // is frame i's sound static MAY-liveness (per-byte offsets) at that
    // frame's resume pc, or `None` when unknown (⇒ don't skip — full
    // compare, the sound direction). Built in `should_prune`.
    // Kernel-aligned idmap (verifier.c v6.15 `check_ids` in regsafe at
    // STACK_ITER L18583): iter ids are minted fresh by every
    // `bpf_iter_*_new` call, so literal `old.id == cur.id` always fails
    // when an iter slot is re-initialized (e.g. nested iters: each outer
    // iteration recreates the inner iter at the same stack slot with a
    // fresh id). Build a per-comparison map `old_id → cur_id` and check
    // for consistency: a given old id may map to exactly one cur id
    // across the comparison.
    let mut iter_idmap: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    // Kernel `stacksafe` per-byte `slot_type` comparison (verifier.c:19708-19762,
    // the `StackSlotKind` block below): a byte one path wrote via a helper
    // (`STACK_MISC`) and a byte another path never wrote (`STACK_INVALID`)
    // must NOT look identical, or the two paths wrongly subsume each
    // other. The faithful per-byte kind rule is unconditional.
    for (frame_i, (old_frame, new_frame)) in old.frames.iter().zip(cur.frames.iter()).enumerate() {
        let all_offsets: HashSet<i16> = old_frame
            .stack
            .slot_offsets()
            .into_iter()
            .chain(new_frame.stack.slot_offsets())
            .collect();

        // Per-frame liveness for the clean_verifier_state skip. `None`
        // (frame liveness unknown) ⇒ no skip for this frame (full
        // compare — the sound direction).
        let frame_ls = frame_live_slots.get(frame_i).and_then(|o| o.as_ref());

        // Kernel stacksafe allocation-boundary gate. EXACT mode
        // (verifier.c:19800): any old-allocation byte at
        // `i >= cur->allocated_stack` fails outright — old INVALID bytes
        // included — so old_alloc > cur_alloc is an immediate mismatch.
        if force_exact && old_frame.stack.allocated_stack() > new_frame.stack.allocated_stack() {
            return false;
        }

        // Kernel `scalar_reg_for_stack` slot-pair rule (stacksafe
        // verifier.c:19736): when BOTH slots read as scalars — (a) a
        // full 8-byte scalar spill (`is_spilled_scalar_reg64`: kernel
        // slot_type[0]==SPILL, i.e. alivio's byte base+7 under the
        // top-down↔bottom-up mirror, plus base anchor SPILL + scalar),
        // or (b) `is_stack_all_misc`: every byte MISC or (privileged)
        // INVALID/never-written — the whole slot compares as ONE
        // regsafe scalar (old imprecise ⇒ covers ANY cur; precise ⇒
        // range_within+tnum_in; all-misc reads as the unbound
        // imprecise fake) and the per-byte kind walk NEVER runs for
        // it (`i += BPF_REG_SIZE - 1; continue`). Without this rule a
        // (Spill, None) byte (cache spilled, cur never written) falls
        // to the catch-all kind mismatch and MISSes where the kernel
        // HITs. Slots consumed here skip their per-byte checks below.
        let mut scalar_pair_slots: HashSet<i16> = HashSet::new();
        if !force_exact {
            let mut seen_bases: HashSet<i16> = HashSet::new();
            for &offset in &all_offsets {
                let base = offset.div_euclid(8) * 8;
                if !seen_bases.insert(base) {
                    continue;
                }
                use crate::analysis::machine::stack_state::StackSlotKind::*;
                // Kernel stacksafe allocation-boundary gate
                // (verifier.c:19816, ordered BEFORE the
                // scalar_reg_for_stack bridge at :19824): for an old byte
                // at `i >= cur->allocated_stack`, only STACK_INVALID
                // (:19806) or privileged STACK_MISC (:19809) may skip;
                // any other kind — including an IMPRECISE 8-byte scalar
                // spill — is a hard mismatch ("explored stack has more
                // populated slots than current stack and these slots
                // were used"). The bridge's unbound-cur wildcard never
                // sees the slot.
                if -(base as i32) > new_frame.stack.allocated_stack() as i32 {
                    let all_skippable = (base..base + 8)
                        .all(|b| matches!(old_frame.stack.get_slot_kind(b), None | Some(Misc)));
                    if !all_skippable {
                        if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                            eprintln!(
                                "[stack_miss] pc={} frame={} base={} (alloc-boundary: cur_alloc={})",
                                cur.pc,
                                frame_i,
                                base,
                                new_frame.stack.allocated_stack()
                            );
                        }
                        return false;
                    }
                    // All old bytes INVALID/MISC ⇒ kernel `continue`s
                    // through the slot; nothing on the cur side can exist
                    // beyond its own allocation. Settled — the per-byte
                    // walk below must not re-judge it.
                    scalar_pair_slots.insert(base);
                    continue;
                }
                // None ⇒ not scalar-readable; Some(None) ⇒ unbound
                // (all-misc/uninit); Some(Some(off)) ⇒ real 8-byte
                // scalar spill anchored at `base`.
                let scalar_read =
                    |fr: &crate::analysis::machine::frame_stack::CallFrame| -> Option<Option<()>> {
                        let structural = fr
                            .stack
                            .get_slot(base)
                            .map(|s| {
                                s.iterator.is_some() || s.dynptr.is_some() || s.irq_flag.is_some()
                            })
                            .unwrap_or(false);
                        if structural {
                            return None;
                        }
                        let spill64 = fr.stack.get_slot_kind(base) == Some(Spill)
                            && fr.stack.get_slot_kind(base + 7) == Some(Spill)
                            && fr
                                .stack
                                .get_slot(base)
                                .map(|s| matches!(s.reg_type, RegType::ScalarValue))
                                .unwrap_or(false);
                        if spill64 {
                            return Some(Some(()));
                        }
                        let all_misc = (base..base + 8)
                            .all(|b| matches!(fr.stack.get_slot_kind(b), Some(Misc) | None));
                        if all_misc {
                            return Some(None);
                        }
                        None
                    };
                let (Some(o), Some(c)) = (scalar_read(old_frame), scalar_read(new_frame)) else {
                    continue;
                };
                // regsafe scalar under !exact (verifier.c:18357): an
                // imprecise old covers any scalar cur; a precise old
                // needs range_within + tnum_in (the unbound cur is only
                // covered by a full-range old).
                let ok = match o {
                    None => true, // unbound old = imprecise ⇒ covers all
                    Some(()) => {
                        let os = old_frame.stack.get_slot(base).unwrap();
                        if !os.precise {
                            true
                        } else {
                            match c {
                                Some(()) => {
                                    let cs = new_frame.stack.get_slot(base).unwrap();
                                    cs.bounds.min >= os.bounds.min
                                        && cs.bounds.max <= os.bounds.max
                                        && tnum_covers(&cs.tnum, &os.tnum)
                                }
                                None => {
                                    os.bounds.min == i64::MIN
                                        && os.bounds.max == i64::MAX
                                        && os.tnum.mask == u64::MAX
                                }
                            }
                        }
                    }
                };
                if !ok {
                    if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                        eprintln!(
                            "[stack_miss] pc={} frame={} base={} (scalar-pair regsafe)",
                            cur.pc, frame_i, base
                        );
                    }
                    return false;
                }
                scalar_pair_slots.insert(base);
            }
        }

        for offset in all_offsets {
            if scalar_pair_slots.contains(&(offset.div_euclid(8) * 8)) {
                continue;
            }
            // Dead-slot skip: if no byte in this 8-byte slot is live at
            // frame i's resume pc, the kernel would have STACK_INVALID'd
            // it — skip, mirroring stacksafe. ITER / DYNPTR / IRQ slots
            // are semantically live regardless of byte-liveness (kernel
            // `bpf_stack_slot_alive` keeps them alive), so never skip
            // those. Conservative 8-byte span: any live byte → keep
            // (fewer skips = sound direction).
            if let Some(ls) = frame_ls
                && !(offset..offset.saturating_add(8)).any(|b| ls.contains(&b))
            {
                let structural = |fr: &crate::analysis::machine::frame_stack::CallFrame| {
                    fr.stack
                        .get_slot(offset)
                        .map(|s| s.iterator.is_some() || s.dynptr.is_some() || s.irq_flag.is_some())
                        .unwrap_or(false)
                };
                if !structural(old_frame) && !structural(new_frame) {
                    continue;
                }
            }

            // Kernel `stacksafe` per-byte `slot_type` rule (verifier.c v6.15
            // L19690-L19760). `get_slot_kind` returns `None` for a never-written
            // byte (`STACK_INVALID`).
            //   - old == STACK_INVALID  → "explored, doesn't matter": old
            //     covers any cur, so this byte never blocks the prune.
            //   - old written, cur == STACK_INVALID → slot_types differ → the
            //     states are NOT equivalent.
            //   - both written: kinds must match, except a cur `STACK_ZERO`
            //     satisfies an old `STACK_MISC` (zero is a more-specific misc).
            //     For MISC/ZERO scalar bytes there is no spilled value to
            //     compare, so the byte is settled here; only `STACK_SPILL`
            //     falls through to the reg-level type/precision checks below.
            {
                use crate::analysis::machine::stack_state::StackSlotKind::*;
                let ok = old_frame.stack.get_slot_kind(offset);
                let nk = new_frame.stack.get_slot_kind(offset);
                match (ok, nk) {
                    (None, _) => continue,
                    // Kernel stacksafe:19742 — `env->allow_uninit_stack &&
                    // old slot_type == STACK_MISC -> continue`, BEFORE the
                    // scalar_reg_for_stack arm and the per-byte kind rule.
                    // Privileged loads (alivio's model, like test_loader as
                    // root) may read uninit stack, so an old MISC byte
                    // covers ANY cur byte — including a never-written one.
                    // EXACT compares still require equal kinds (kernel
                    // 19733).
                    (Some(Misc), _) if !force_exact => continue,
                    (Some(Spill), Some(Spill)) => { /* fall through to reg checks */ }
                    (Some(Misc), Some(Misc | Zero)) | (Some(Zero), Some(Zero)) => continue,
                    // Kernel `scalar_reg_for_stack` (verifier.c:19686, applied at
                    // stacksafe:19737 BEFORE the per-byte kind rule): a 64-bit
                    // scalar spill and an all-MISC slot compare as SCALARS —
                    // "load from all slots MISC produces unbound scalar". MISC
                    // reads as `unbound_reg` (unknown IMPRECISE scalar), and
                    // regsafe's scalar rule under !exact is: imprecise old
                    // covers anything; precise old needs range_within+tnum_in
                    // (an unbound cur is only covered by a full-range old).
                    // Under EXACT the fake regs must be regs_exact → mismatch.
                    (Some(Misc), Some(Spill)) | (Some(Spill), Some(Misc)) if !force_exact => {
                        // Kernel preconditions are SLOT-granular: the spill side
                        // must be a 64-BIT SCALAR spill (is_spilled_scalar_reg64:
                        // slot_type[0]==SPILL && scalar), and the misc side's
                        // WHOLE 8-byte slot must be all STACK_MISC or (privileged)
                        // STACK_INVALID — STACK_ZERO bytes disqualify. Only then
                        // do both sides read as scalars (MISC ⇒ unbound
                        // imprecise) and regsafe's !exact scalar rule applies.
                        let slot_base = offset.div_euclid(8) * 8;
                        let all_misc = |fr: &crate::analysis::machine::frame_stack::CallFrame| {
                            (slot_base..slot_base + 8)
                                .all(|b| matches!(fr.stack.get_slot_kind(b), Some(Misc) | None))
                        };
                        // Kernel `is_spilled_scalar_reg64` = slot_type[0] ==
                        // STACK_SPILL, i.e. a FULL 8-byte scalar spill (alivio
                        // mirror: base AND base+7 Spill). A sub-8 spill leaves
                        // the kernel's slot_type[0] non-SPILL, so
                        // `scalar_reg_for_stack` returns NULL and the per-byte
                        // walk TYPEFAILs the (SPILL, MISC) byte — a
                        // base-anchor-only check would HIT sub-8 spills vs
                        // all-misc where the kernel misses.
                        let scalar_spill64 =
                            |fr: &crate::analysis::machine::frame_stack::CallFrame| {
                                matches!(fr.stack.get_slot_kind(slot_base), Some(Spill))
                                    && matches!(fr.stack.get_slot_kind(slot_base + 7), Some(Spill))
                                    && fr
                                        .stack
                                        .get_slot(slot_base)
                                        .map(|s| matches!(s.reg_type, RegType::ScalarValue))
                                        .unwrap_or(false)
                            };
                        let covered = if matches!(ok, Some(Spill)) {
                            // old spill vs cur misc: old fake scalar covers the
                            // unbound cur iff imprecise (or full-range precise).
                            scalar_spill64(old_frame)
                                && all_misc(new_frame)
                                && old_frame
                                    .stack
                                    .get_slot(slot_base)
                                    .map(|s| {
                                        !s.precise
                                            || (s.bounds.min == i64::MIN
                                                && s.bounds.max == i64::MAX
                                                && s.tnum.mask == u64::MAX)
                                    })
                                    .unwrap_or(false)
                        } else {
                            // old misc vs cur spill: old fake = unbound
                            // imprecise scalar — covers any scalar cur.
                            all_misc(old_frame) && scalar_spill64(new_frame)
                        };
                        if covered {
                            continue;
                        }
                        if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                            let kinds = |fr: &crate::analysis::machine::frame_stack::CallFrame| {
                                (slot_base..slot_base + 8)
                                    .map(|b| fr.stack.get_slot_kind(b))
                                    .collect::<Vec<_>>()
                            };
                            eprintln!(
                                "[stack_miss] pc={} frame={} off={} base={} old_kinds={:?} new_kinds={:?} old_slot@base={:?} (spill-misc-precond)",
                                cur.pc,
                                frame_i,
                                offset,
                                slot_base,
                                kinds(old_frame),
                                kinds(new_frame),
                                old_frame
                                    .stack
                                    .get_slot(slot_base)
                                    .map(|s| (s.reg_type, s.precise)),
                            );
                        }
                        return false;
                    }
                    (Some(_), None) | (Some(_), Some(_)) => {
                        if std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1") {
                            eprintln!(
                                "[stack_miss] pc={} frame={} off={} old_kind={:?} new_kind={:?}",
                                cur.pc, frame_i, offset, ok, nk
                            );
                        }
                        return false;
                    }
                }
            }

            // Kernel stacksafe: the spilled-register comparison (regsafe on
            // `stack[spi].spilled_ptr`) runs ONCE per slot, gated on byte 7
            // (verifier.c:19796 `if (i % BPF_REG_SIZE != BPF_REG_SIZE - 1)
            // continue;`) — and byte 7 is only reached when it is SPILL (a
            // MISC/INVALID byte 7 was already skipped, incl. the
            // allow_uninit_stack MISC skip at :19742). So a SUB-8-BYTE spill
            // whose remainder is MISC (byte 7 == MISC) gets NO reg
            // comparison: as OLD it covers any cur (the misc remainder reads
            // as an unbound scalar). alivio stores the slot's reg at the BASE
            // byte and iterates per-byte; comparing the reg on EVERY spill
            // byte would be over-strict vs the kernel's byte-7-only rule.
            // Restrict the reg comparison to the base byte, gated on the
            // slot's LAST byte being SPILL in OLD.
            {
                use crate::analysis::machine::stack_state::StackSlotKind;
                let slot_base = offset.div_euclid(8) * 8;
                // Kernel layout mapping (save_register_state, verifier.c:
                // `for (i = BPF_REG_SIZE; i > BPF_REG_SIZE - size; i--)
                // slot_type[i-1] = STACK_SPILL`): the kernel marks spill
                // bytes TOP-DOWN, so ITS byte 7 is SPILL for EVERY spilled
                // reg (any size) — the byte-7 gate only skips slots whose
                // spill ANCHOR was scrubbed by a later partial overwrite.
                // alivio marks spills BOTTOM-UP (Spill at [0..size), Misc
                // above), so the kernel's byte-7 ≡ alivio's BASE byte.
                // Gating on alivio's byte 7 would skip the whole
                // reg/type/precision compare for every sub-8-byte spill.
                let old_anchor_spill =
                    old_frame.stack.get_slot_kind(slot_base) == Some(StackSlotKind::Spill);
                if offset != slot_base || !old_anchor_spill {
                    continue;
                }
            }

            let old_ty = old_frame.stack.get_slot_type(offset);
            let new_ty = new_frame.stack.get_slot_type(offset);
            // Stack-specific subsumption is STRICTER than register
            // `type_subsumed_by`. For registers, `(NotInit, _) => true`
            // is correct: an uninit reg "covers" anything because
            // future reads error anyway. For STACK slots, NotInit
            // means "never written" — semantically a specific state
            // distinct from "written with type X". Pruning cur (with
            // a written slot) against cached (with the slot
            // unwritten) skips exploring cur's continuation, which
            // observes the written slot; cached's continuation never
            // does, so the two are not equivalent.
            //
            // Pattern from `rbtree::rbtree_add_and_remove_array` and
            // `test_cls_redirect::cls_redirect`: slot reused across
            // paths with different types; cached state with NotInit
            // (or earlier-spilled scalar) wrongly subsumes a path
            // that has spilled `PtrToOwnedKptr` / `PtrToPacket` to
            // the same offset.
            if !stack_slot_type_subsumed_by(&new_ty, &old_ty) {
                if crate::analysis::trace_pc_in_range(cur.pc)
                    && std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1")
                {
                    eprintln!(
                        "[stack_miss] pc={} frame={} off={} old_ty={:?} new_ty={:?} (slot-type)",
                        cur.pc, frame_i, offset, old_ty, new_ty
                    );
                }
                return false;
            }

            // Precision: a precise *cached* slot requires the new slot
            // to fall inside its range/tnum (kernel `regsafe` SCALAR
            // verifier.c v6.15 L18357: precise old → range_within +
            // tnum_in; non-precise old → free pass when live). Earlier
            // we keyed on `new_s.precise` and demanded EXACT — that's
            // stricter than the kernel and blocks may_goto-bounded
            // loops where a body memory access precision-marks the
            // counter (cond_break1/2/3).
            let old_slot = old_frame.stack.get_slot(offset);
            let new_slot = new_frame.stack.get_slot(offset);
            if let (Some(old_s), Some(new_s)) = (old_slot, new_slot)
                && old_s.precise
            {
                if !tnum_covers(&new_s.tnum, &old_s.tnum) {
                    if crate::analysis::trace_pc_in_range(cur.pc)
                        && std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1")
                    {
                        eprintln!(
                            "[stack_miss] pc={} frame={} off={} old_tn={:?} new_tn={:?} (precise-tnum)",
                            cur.pc, frame_i, offset, old_s.tnum, new_s.tnum
                        );
                    }
                    return false;
                }
                if !(old_s.bounds.min <= new_s.bounds.min && new_s.bounds.max <= old_s.bounds.max) {
                    if crate::analysis::trace_pc_in_range(cur.pc)
                        && std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1")
                    {
                        eprintln!(
                            "[stack_miss] pc={} frame={} off={} old=[{},{}] new=[{},{}] (precise-bounds)",
                            cur.pc,
                            frame_i,
                            offset,
                            old_s.bounds.min,
                            old_s.bounds.max,
                            new_s.bounds.min,
                            new_s.bounds.max
                        );
                    }
                    return false;
                }
            }

            // open-coded iterator identity.
            //
            // An Active/Drained iterator slot represents a specific
            // loop instance (id minted at `*_new`). A cached state
            // subsumes the current one at this slot only when both
            // carry the exact same annotation — matching kind, state,
            // and id. Mismatched iterator state, mismatched id, or one
            // side carrying an annotation and the other not are all
            // semantically distinct program points and must not
            // collapse into a single pruned state.
            //
            // Non-precise loop-varying scalars are allowed to converge
            // via the existing non-precise superset rule above —
            // this check is about the iterator identity itself, not
            // the loop variable.
            // `depth` is intentionally ignored — it grows monotonically
            // per iter_next ACTIVE-fork (kernel `iter.depth`) and is
            // used by the inf-loop detector and `widen_imprecise_scalars`
            // to keep iterations distinguishable, NOT by subsumption.
            // Kernel `states_equal(RANGE_WITHIN)` for iter_next call
            // sites doesn't compare `iter.depth` either; convergence
            // here is exactly what allows e.g. `i++; while(iter_next)`
            // loops to terminate.
            let old_iter = old_slot.and_then(|s| s.iterator);
            let new_iter = new_slot.and_then(|s| s.iterator);
            let iter_eq_modulo_depth = match (old_iter, new_iter) {
                (None, None) => true,
                (Some(a), Some(b)) => {
                    if a.kind != b.kind || a.state != b.state {
                        false
                    } else {
                        // check_ids: id may be remapped, but consistently.
                        match iter_idmap.get(&a.id) {
                            Some(&mapped) => mapped == b.id,
                            None => {
                                iter_idmap.insert(a.id, b.id);
                                true
                            }
                        }
                    }
                }
                _ => false,
            };
            if !iter_eq_modulo_depth {
                if crate::analysis::trace_pc_in_range(cur.pc)
                    && std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1")
                {
                    eprintln!(
                        "[stack_miss] pc={} frame={} off={} (iter-identity)",
                        cur.pc, frame_i, offset
                    );
                }
                return false;
            }

            // For packet pointers, also check interval_range subsumption.
            // If old has a proven range but cur doesn't, old does NOT subsume cur,
            // because cur might fail a packet access that old would pass.
            // We need to explore cur to find potential unsafe paths.
            if matches!(new_ty, RegType::PtrToPacket | RegType::PtrToPacketMeta) {
                let old_slot = old_frame.stack.get_slot(offset);
                let new_slot = new_frame.stack.get_slot(offset);
                if let (Some(old_s), Some(new_s)) = (old_slot, new_slot) {
                    use crate::analysis::machine::stack_state::PointerBounds;
                    let old_range = match &old_s.ptr_bounds {
                        Some(PointerBounds::Interval { range, .. }) => *range,
                        _ => None,
                    };
                    let new_range = match &new_s.ptr_bounds {
                        Some(PointerBounds::Interval { range, .. }) => *range,
                        _ => None,
                    };

                    let pkt_fail = matches!((old_range, new_range), (Some(_), None))
                        || matches!((old_range, new_range), (Some(o), Some(n)) if o > n);
                    if pkt_fail {
                        if crate::analysis::trace_pc_in_range(cur.pc)
                            && std::env::var("ALIVIO_DUMP_SUBSUM_MISS").ok().as_deref() == Some("1")
                        {
                            eprintln!(
                                "[stack_miss] pc={} frame={} off={} old_rng={:?} new_rng={:?} (pkt-range)",
                                cur.pc, frame_i, offset, old_range, new_range
                            );
                        }
                        return false;
                    }
                }
            }
        }
    }
    true
}

fn tnum_subsumed_by(cur_state: &State, old_state: &State, live_regs: &HashSet<Reg>) -> bool {
    // Kernel rule: precise → tnum-cover; !precise → accept.
    for &r in live_regs {
        if !old_state.is_reg_precise(r) {
            continue;
        }
        // Kernel `regsafe` compares var_off (the tnum) ONLY in the
        // SCALAR_VALUE arm; pointer types (PTR_TO_MAP_VALUE / PACKET /
        // CTX / …) are compared by their type-specific fields (offset
        // range, id via check_ids, range) and NEVER by var_off. A
        // map-value pointer can carry a STALE precise scalar tnum — e.g.
        // `r0 = 0` (const 0, marked precise) then `r0 = map_lookup()`
        // makes r0 a PtrToMapValue that kept tnum{0,0}+precise, while a
        // sibling path's fresh lookup has tnum unknown. Comparing those
        // meaningless address-tnums would wrongly block subsumption.
        // `domain_subsumed_by` already skips pointers here; this makes
        // the tnum check consistent and kernel-faithful.
        if old_state.types.get(r).is_pointer() || cur_state.types.get(r).is_pointer() {
            continue;
        }
        let cur = cur_state.get_tnum(r);
        let old = old_state.get_tnum(r);
        if !tnum_covers(&cur, &old) {
            return false;
        }
    }
    true
}

/// Check if old tnum covers cur tnum (old's possible values are a superset of cur's).
fn tnum_covers(cur: &Tnum, old: &Tnum) -> bool {
    // Every unknown bit in cur must also be unknown in old
    if cur.mask & !old.mask != 0 {
        return false;
    }
    // For bits that are known in both, the values must match
    let both_known = !cur.mask & !old.mask;
    (cur.value & both_known) == (old.value & both_known)
}

/// Like tnum_subsumed_by but operates on call stack frames instead of full states.
fn caller_tnum_subsumed_by(
    cur_frame: &crate::analysis::machine::frame_stack::CallFrame,
    old_frame: &crate::analysis::machine::frame_stack::CallFrame,
    regs: &HashSet<Reg>,
) -> bool {
    for &r in regs {
        let cur = cur_frame
            .caller_tnums
            .get(&r)
            .copied()
            .unwrap_or(Tnum::UNKNOWN);
        let old = old_frame
            .caller_tnums
            .get(&r)
            .copied()
            .unwrap_or(Tnum::UNKNOWN);
        if !tnum_covers(&cur, &old) {
            return false;
        }
    }
    true
}
