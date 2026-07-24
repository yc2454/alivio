// src/analysis/transfer/branch/refinement.rs

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use crate::ast::{CmpOp, Instr, Operand};
/// Promote a pointer type across all stack frames by ref/ptr id.
/// `should_promote` checks if a slot's type matches, `promote` returns the new type.
fn promote_stack_slots_all_frames(
    state: &mut State,
    should_promote: impl Fn(&RegType) -> bool,
    promote: impl Fn(&RegType) -> RegType,
) {
    for frame in state.frames.iter_mut() {
        let offsets: Vec<i16> = frame.stack.slot_offsets();
        for k in offsets {
            let ty = frame.stack.get_slot_type(k);
            if should_promote(&ty) {
                frame.stack.set_slot_type(k, promote(&ty), None);
            }
        }
    }
}

/// After `apply_jmp_constraints` tightens bounds on `left` in both branch
/// states, propagate those same refinements to every register and stack slot
/// that shares `left`'s scalar id.  Called once per branch in `transfer_if`.
pub(crate) fn propagate_scalar_links(then_s: &mut State, else_s: &mut State, left: Reg) {
    fanout_scalar_bounds(then_s, left);
    fanout_scalar_bounds(else_s, left);
}

/// Tighten every scalar-linked register/slot in `state` to the bounds that
/// `left` has *after* the branch constraint was applied.
fn fanout_scalar_bounds(state: &mut State, left: Reg) {
    // 3ab6@937 probe: id presence at the fanout entry.
    if crate::analysis::trace_pc_in_range(state.pc) {
        eprintln!(
            "[fanout-entry] pc={} left={:?} scalar_id={:?}",
            state.pc, left, state.scalar_id(left)
        );
    }
    let id = match state.scalar_id(left) {
        Some(id) => id,
        None => return,
    };

    let linked: Vec<Reg> = state
        .regs_with_scalar_id(id)
        .into_iter()
        .filter(|&r| r != left && r != Reg::Zero)
        .collect();

    let (lo, hi) = state.domain.get_interval(left);
    let tnum = state.get_tnum(left);
    // 3ab6@937 probe: the tnum lifecycle at the crossing-1 fanout.
    if crate::analysis::trace_pc_in_range(state.pc) {
        eprintln!(
            "[fanout] pc={} left={:?} ivl=[{},{}] tnum={:?} linked={:?} r9(id={:?} ty={:?} tn={:?})",
            state.pc, left, lo, hi, tnum, linked,
            state.scalar_id(Reg::R9), state.types.get(Reg::R9),
            state.get_tnum(Reg::R9)
        );
    }
    // Kernel `BPF_ADD_CONST` delta of the narrowed base (verifier.c
    // `sync_linked_regs`): a linked reg `R == base + (R.off - left.off)`,
    // so propagate `left`'s range SHIFTED by that per-reg delta. `left.off`
    // is 0 unless `left` itself is an add-const link. Always 0 in BCF mode
    // (scalar_id_off stays empty there) ⇒ delta 0 ⇒ unchanged behavior.
    let left_off = state.scalar_id_off(left).unwrap_or(0);

    // ── Registers ───────────────────────────────────────────────────────────
    for r in &linked {
        let r = *r;
        // Skip registers that have since become pointers: the zone domain
        // stores packet-pointer offsets as huge sentinel values in its DBM,
        // and intersecting them with scalar bounds corrupts the domain.
        if state.types.get(r) != RegType::ScalarValue {
            continue;
        }
        let delta = state.scalar_id_off(r).unwrap_or(0).saturating_sub(left_off);
        let (lo, hi, tnum) = if delta == 0 {
            (lo, hi, tnum)
        } else {
            (lo.saturating_add(delta), hi.saturating_add(delta), tnum.add_imm(delta))
        };
        let (r_lo, r_hi) = state.domain.get_interval(r);
        // Guard: skip if the new bound would make this register's
        // interval empty.  That can happen when the zone domain has
        // accumulated anchor-relative constraints that manifest as
        // large sentinel values in the scalar interval.  In those
        // cases the fan-out is either a no-op (if IDs are stale) or
        // would produce a false inconsistency.  A future pass
        //  will clean up stale IDs at merge points; for now
        // we be conservative and only tighten when it's safe.
        if lo > r_hi || hi < r_lo {
            continue;
        }
        // Tighten (intersect) only.
        if lo > r_lo {
            state.domain.assume_ge_imm(r, lo);
        }
        if hi < r_hi {
            state.domain.assume_le_imm(r, hi);
        }
        let r_tnum = state.get_tnum(r);
        if let Some(t) = r_tnum.intersect(tnum) {
            let now_const = t.is_const();
            state.set_tnum(r, t);
            // Kernel sync_linked_regs = copy_register_state(reg, known_reg)
            // (verifier.c:17558) — the synced reg inherits the known reg's
            // bcf_expr, which __mark_reg_known CLEARED when the branch made
            // it const (:2500). Mirror: a linked reg synced to a tnum-const
            // drops its stale symbolic binding, so its next reference (or a
            // later spill/fill of it) materializes the bcf_val literal —
            // matching the kernel's folded const-vs-const conds.
            if now_const
                && let Some(idx) = r.bcf_idx()
                && let Some(bcf) = state.bcf.as_mut()
            {
                bcf.clear_reg(idx);
            }
        }
    }

    // ── Stack slots ──────────────────────────────────────────────────────────
    // Only propagate to scalar slots; apply the same consistency guard as for
    // registers so that a subsequent fill_at doesn't load inconsistent bounds.
    let state_pc = state.pc;
    for frame in state.frames.iter_mut() {
        for (_, slot) in frame.stack.iter_mut() {
            if slot.scalar_id != Some(id) {
                continue;
            }
            if slot.reg_type != RegType::ScalarValue {
                continue;
            }
            // Kernel sync_linked_regs delta for spilled links: the slot
            // holds `base + slot_off` while `left` holds `base + left_off`,
            // so left's refined range applies to the slot SHIFTED by
            // (slot_off - left_off). Without the shift a branch on an
            // add-const reg (e.g. r8 = slot + 30) writes r8's range raw
            // into the base slot — an unsound tightening
            // (slot[0,65535] -> [30,65535]).
            let delta = slot.scalar_id_off.unwrap_or(0).saturating_sub(left_off);
            let (lo, hi, tnum) = if delta == 0 {
                (lo, hi, tnum)
            } else {
                (lo.saturating_add(delta), hi.saturating_add(delta), tnum.add_imm(delta))
            };
            if lo > slot.bounds.max || hi < slot.bounds.min {
                continue;
            }
            let new_min = if lo > slot.bounds.min { lo } else { slot.bounds.min };
            let new_max = if hi < slot.bounds.max { hi } else { slot.bounds.max };
            if new_min > new_max {
                continue; // Would make bounds inconsistent — skip
            }
            if (new_min, new_max) != (slot.bounds.min, slot.bounds.max)
                && std::env::var("ZOVIA_DUMP_SLOT_FANOUT").ok().as_deref() == Some("1")
            {
                eprintln!(
                    "[slot-fanout] pc={} left={:?} left_off={} slot_bounds=[{},{}] -> [{},{}] from=[{},{}]",
                    state_pc, left, left_off, slot.bounds.min, slot.bounds.max,
                    new_min, new_max, lo, hi
                );
            }
            slot.bounds.min = new_min;
            slot.bounds.max = new_max;
            if let Some(t) = slot.tnum.intersect(tnum) {
                slot.tnum = t;
                // Same copy_register_state mirror as the reg half: a slot
                // synced to a tnum-const drops its spilled expr (kernel
                // syncs the spilled_ptr with the known reg's cleared
                // bcf_expr) — the next fill restores an unbound const.
                if t.is_const() {
                    slot.bcf_expr = None;
                }
            }
        }
    }
}

/// `if r1 == r2` / `if r1 != r2` jeq-infer: when one operand is already
/// a non-null pointer with an id (e.g. `PtrToMapValue`) and the branch
/// implies r1 == r2, propagate the non-null type to the other operand
/// if it's the matching nullable variant (same id). Mirrors upstream
/// `find_equal_scalars` / jeq_infer_not_null logic.
fn jeq_infer_not_null(state: &mut State, left: Reg, right: Reg, eq_branch: bool) {
    if !eq_branch {
        return;
    }
    let lty = state.types.get(left);
    let rty = state.types.get(right);
    // If `r1 == r2` and one side is a known non-null pointer, the other
    // (if it's the matching nullable variant) is also non-null. Mirrors
    // upstream `find_equal_scalars` / jeq_infer_not_null. Ids don't need
    // to match — value-equality of two registers means they alias the
    // same kernel pointer regardless of how each was tracked.
    if matches!(lty, RegType::PtrToMapValue { .. })
        && matches!(rty, RegType::PtrToMapValueOrNull { .. })
    {
        maybe_promote_map_val(state, right);
        return;
    }
    if matches!(rty, RegType::PtrToMapValue { .. })
        && matches!(lty, RegType::PtrToMapValueOrNull { .. })
    {
        maybe_promote_map_val(state, left);
        return;
    }
    // Extend to acquire-tracked pointer families: a JEQ between a
    // non-null variant and the matching nullable variant promotes the
    // nullable side on the eq branch, regardless of ref_id (the JEQ
    // itself proves they alias). Without this, refinement can only flow
    // across registers via shared ref_id — which we deliberately don't
    // link when ref_id is `None`, see `same_acquired_pointer`.
    if let Some(reg) = nullable_partner(&lty, &rty) {
        match reg {
            JeqPartner::Right => promote_nullable(state, right, &rty),
            JeqPartner::Left => promote_nullable(state, left, &lty),
        }
    }
}

enum JeqPartner {
    Left,
    Right,
}

fn nullable_partner(lty: &RegType, rty: &RegType) -> Option<JeqPartner> {
    if is_non_null_acquired(lty) && is_nullable_matching(lty, rty) {
        return Some(JeqPartner::Right);
    }
    if is_non_null_acquired(rty) && is_nullable_matching(rty, lty) {
        return Some(JeqPartner::Left);
    }
    None
}

fn is_non_null_acquired(ty: &RegType) -> bool {
    matches!(
        ty,
        RegType::PtrToSocket { .. }
            | RegType::PtrToSockCommon { .. }
            | RegType::PtrToTcpSock { .. }
            | RegType::PtrToCpumask { .. }
            | RegType::PtrToArena { .. }
            | RegType::PtrToCgroup { .. }
            | RegType::PtrToOwnedKptr { .. }
    )
}

fn is_nullable_matching(non_null: &RegType, nullable: &RegType) -> bool {
    matches!(
        (non_null, nullable),
        (RegType::PtrToSocket { .. }, RegType::PtrToSocketOrNull { .. })
            | (
                RegType::PtrToSockCommon { .. },
                RegType::PtrToSockCommonOrNull { .. }
            )
            | (
                RegType::PtrToTcpSock { .. },
                RegType::PtrToTcpSockOrNull { .. }
            )
            | (
                RegType::PtrToCpumask { .. },
                RegType::PtrToCpumaskOrNull { .. }
            )
            | (RegType::PtrToArena { .. }, RegType::PtrToArenaOrNull { .. })
            | (RegType::PtrToCgroup { .. }, RegType::PtrToCgroupOrNull { .. })
            | (
                RegType::PtrToOwnedKptr { .. },
                RegType::PtrToOwnedKptrOrNull { .. }
            )
    )
}

fn promote_nullable(state: &mut State, reg: Reg, ty: &RegType) {
    if let Some(non_null) = ty.to_non_null() {
        state.types.set(reg, non_null);
    }
}

/// Refines register types based on the outcome of a conditional branch.
pub(crate) fn refine_branch(state: &mut State, instr: &Instr, branch_taken: bool) {
    // jeq_infer_not_null: `if r1 (==|!=) r2`
    if let Instr::If {
        op,
        left,
        right: Operand::Reg(right),
        ..
    } = instr
    {
        let eq_branch = match op {
            CmpOp::Eq => branch_taken,
            CmpOp::Ne => !branch_taken,
            _ => return,
        };
        jeq_infer_not_null(state, *left, *right, eq_branch);
        return;
    }

    if let Instr::If {
        op,
        left,
        right: Operand::Imm(0),
        ..
    } = instr
    {
        // Determine if this path implies reg is non-null
        let is_non_null = match op {
            CmpOp::Ne => branch_taken,  // if (reg != 0) goto => taken means non-null
            CmpOp::Eq => !branch_taken, // if (reg == 0) goto => fallthrough means non-null
            CmpOp::SGe | CmpOp::UGe | CmpOp::SGt | CmpOp::UGt => branch_taken,
            CmpOp::SLe | CmpOp::ULe | CmpOp::SLt | CmpOp::ULt => !branch_taken,
            CmpOp::Test => branch_taken,
        };

        // Existing map value promotion
        if is_non_null {
            maybe_promote_map_val(state, *left);
            maybe_promote_btf_id(state, *left);
            maybe_promote_mem(state, *left);
        } else {
            // Kernel-mirror `mark_ptr_or_null_reg` null-branch arm
            // (verifier.c:17318-17328): when the branch proves the OR_NULL
            // ptr is NULL, demote `type` to SCALAR_VALUE and pin var_off /
            // bounds to const-0. Without this, `record_path_cond`-style
            // discharge sites that fire on the null branch see the reg as
            // non-scalar and skip the conjunct (kernel records it, since
            // its scalar typing happened at the branch). Closes the
            // inspektor-gadget seccomp PC 142 missing-conjunct gap: kernel
            // emits `(K0_64 JEQ K0_64)` for the PC 89 `if r0 == 0`
            // fall-through after map_lookup_elem's R0=PtrToMapValueOrNull.
            // Acquired-ref OR_NULL types (Socket / Cgroup / OwnedKptr / …)
            // already get this in `maybe_refine_acquired_ref` below.
            maybe_demote_or_null_to_scalar(state, *left);
        }

        // refine acquired references (handles both paths)
        maybe_refine_acquired_ref(state, *left, is_non_null);
    }
}

/// Null-branch mirror of [`maybe_promote_map_val`] / [`maybe_promote_btf_id`]:
/// on the side where the OR_NULL pointer is proved NULL, demote every
/// register sharing the OR_NULL `id` to `SCALAR_VALUE` and pin its abstract
/// value to const-0. Mirrors kernel `mark_ptr_or_null_reg` (verifier.c:17318).
///
/// Acquired-ref OR_NULL families (Socket / TcpSock / Cpumask / Arena /
/// Cgroup / Task / OwnedKptr / MapKptr) are handled by
/// `maybe_refine_acquired_ref`, which also unrefs.
fn maybe_demote_or_null_to_scalar(state: &mut State, reg: Reg) {
    let target_id = match state.types.get(reg) {
        RegType::PtrToMapValueOrNull { id, .. } => id,
        // Acquired-ref BTF OrNull (ref_id Some) is owned by
        // `maybe_refine_acquired_ref`, which both demotes AND releases the
        // ref on the null branch. Demoting it to ScalarValue here would
        // erase the ref_id before that runs, leaking the reference.
        RegType::PtrToBtfIdOrNull { id, ref_id: None, .. } => id,
        _ => return,
    };
    for r in Reg::ALL {
        let same_id = match state.types.get(r) {
            RegType::PtrToMapValueOrNull { id, .. } if id == target_id => true,
            RegType::PtrToBtfIdOrNull { id, ref_id: None, .. } if id == target_id => true,
            _ => false,
        };
        if same_id {
            state.types.set(r, RegType::ScalarValue);
            state.domain.assign_imm(r, 0);
            state.set_tnum(r, crate::domains::tnum::Tnum::constant(0));
        }
    }
}

/// Promotes a Nullable Map Pointer to a Safe Map Pointer.
fn maybe_promote_map_val(state: &mut State, reg: Reg) {
    let (target_id, _target_map_idx) = match state.types.get(reg) {
        RegType::PtrToMapValueOrNull { id, map_idx, .. } => (id, map_idx),
        _ => return,
    };
    for r in Reg::ALL {
        if let RegType::PtrToMapValueOrNull { id, map_idx, map_uid } = state.types.get(r)
            && id == target_id
        {
            state.types.set(
                r,
                RegType::PtrToMapValue {
                    id,
                    offset: Some(0),
                    map_idx,
                    map_uid,
                    rdonly: false,
                },
            );
            // Initialize PtrOffset tracking for interval domain
            state.domain.init_map_value_ptr(r);
            // BCF symbolic anchor (α Step 1): map-value pointers anchor at
            // offset 0 from the value's start, analogous to R10 anchoring
            // at 0 in `materialize_reg64`. Subsequent `handle_add`/
            // `handle_sub` hooks build the symbolic offset incrementally.
            // The refinement at the map-region rejection site reads this
            // expression directly.
            if let Some(bcf) = state.bcf.as_mut()
                && let Some(i) = r.bcf_idx() {
                    let zero = bcf.add_val64(0);
                    bcf.bind_reg(i, zero);
                }
        }
    }
    promote_stack_slots_all_frames(
        state,
        |ty| matches!(ty, RegType::PtrToMapValueOrNull { id, .. } if *id == target_id),
        |ty| match ty {
            RegType::PtrToMapValueOrNull { id, map_idx, map_uid } => RegType::PtrToMapValue {
                id: *id,
                offset: Some(0),
                map_idx: *map_idx,
                map_uid: *map_uid,
                rdonly: false,
            },
            _ => unreachable!(),
        },
    );
}

fn maybe_promote_btf_id(state: &mut State, reg: Reg) {
    let target_id = match state.types.get(reg) {
        RegType::PtrToBtfIdOrNull { id, .. } => id,
        _ => return,
    };
    for r in Reg::ALL {
        if let RegType::PtrToBtfIdOrNull {
            id,
            type_name,
            flags,
            ref_id,
        } = state.types.get(r)
            && id == target_id
        {
            state.types.set(
                r,
                RegType::PtrToBtfId {
                    type_name,
                    flags,
                    ref_id,
                },
            );
        }
    }
    promote_stack_slots_all_frames(
        state,
        |ty| matches!(ty, RegType::PtrToBtfIdOrNull { id, .. } if *id == target_id),
        |ty| match ty {
            RegType::PtrToBtfIdOrNull {
                id: _,
                type_name,
                flags,
                ref_id,
            } => RegType::PtrToBtfId {
                type_name,
                flags: *flags,
                ref_id: *ref_id,
            },
            _ => unreachable!(),
        },
    );
}

fn maybe_promote_mem(state: &mut State, reg: Reg) {
    let (target_id, _) = match state.types.get(reg) {
        RegType::PtrToAllocMemOrNull { id, mem_size, .. } => (id, mem_size),
        _ => return,
    };
    for r in Reg::ALL {
        if let RegType::PtrToAllocMemOrNull { id, mem_size, ref_id, dynptr_id, rdonly } = state.types.get(r)
            && id == target_id
        {
            state.types.set(
                r,
                RegType::PtrToAllocMem { id, mem_size, ref_id, dynptr_id, rdonly },
            );
        }
    }
    promote_stack_slots_all_frames(
        state,
        |ty| matches!(ty, RegType::PtrToAllocMemOrNull { id, .. } if *id == target_id),
        |ty| match ty {
            RegType::PtrToAllocMemOrNull {
                id,
                mem_size,
                ref_id,
                dynptr_id,
                rdonly,
            } => RegType::PtrToAllocMem {
                id: *id,
                mem_size: *mem_size,
                ref_id: *ref_id,
                dynptr_id: *dynptr_id,
                rdonly: *rdonly,
            },
            _ => unreachable!(),
        },
    );
}

/// True if two reg types are the same nullable acquire-tracked
/// pointer family with the same ref_id — i.e. a null check on one
/// should refine the other along the same branch. Covers all
/// acquire-style RegTypes (sockets / cpumask / arena / owned-kptr).
///
/// Two `None` ids are NOT considered linked — they describe pointers
/// the verifier never assigned a release-tracking identity to (e.g.
/// successive `bpf_sk_fullsock(skb->sk)` calls produce two distinct
/// nullable sockets, neither acquired). Cross-register null promotion
/// across such pairs caused the `verifier_jeq_infer_not_null::
/// unchanged_for_jeq_false_branch` FALSE_ACCEPT.
fn same_acquired_pointer(t1: &RegType, t2: &RegType) -> bool {
    fn linked(id1: &Option<u32>, id2: &Option<u32>) -> bool {
        id1.is_some() && id1 == id2
    }
    match (t1, t2) {
        (
            RegType::PtrToSocketOrNull { ref_id: id1 },
            RegType::PtrToSocketOrNull { ref_id: id2 },
        ) => linked(id1, id2),
        (
            RegType::PtrToSockCommonOrNull { ref_id: id1 },
            RegType::PtrToSockCommonOrNull { ref_id: id2 },
        ) => linked(id1, id2),
        (RegType::PtrToTcpSockOrNull { id: id1 }, RegType::PtrToTcpSockOrNull { id: id2 }) => {
            linked(id1, id2)
        }
        (
            RegType::PtrToCpumaskOrNull { ref_id: id1 },
            RegType::PtrToCpumaskOrNull { ref_id: id2 },
        ) => linked(id1, id2),
        (
            RegType::PtrToArenaOrNull { ref_id: id1, .. },
            RegType::PtrToArenaOrNull { ref_id: id2, .. },
        ) => linked(id1, id2),
        (
            RegType::PtrToCgroupOrNull { ref_id: id1 },
            RegType::PtrToCgroupOrNull { ref_id: id2 },
        ) => linked(id1, id2),
        (
            RegType::PtrToOwnedKptrOrNull { ref_id: id1, .. },
            RegType::PtrToOwnedKptrOrNull { ref_id: id2, .. },
        ) => linked(id1, id2),
        (
            RegType::PtrToTaskOrNull { ref_id: id1 },
            RegType::PtrToTaskOrNull { ref_id: id2 },
        ) => linked(id1, id2),
        (
            RegType::PtrToBtfIdOrNull { ref_id: id1, .. },
            RegType::PtrToBtfIdOrNull { ref_id: id2, .. },
        ) => linked(id1, id2),
        _ => false,
    }
}

/// On the non-NULL path: promotes PtrToSocketOrNull → PtrToSocket (ref stays active).
/// On the NULL path: releases the reference from tracking.
fn maybe_refine_acquired_ref(state: &mut State, reg: Reg, is_non_null: bool) {
    let reg_type = state.types.get(reg);
    let target_ref_id = match reg_type {
        RegType::PtrToSocketOrNull { ref_id }
        | RegType::PtrToSockCommonOrNull { ref_id }
        | RegType::PtrToTcpSockOrNull { id: ref_id }
        | RegType::PtrToCpumaskOrNull { ref_id }
        | RegType::PtrToArenaOrNull { ref_id, .. }
        | RegType::PtrToCgroupOrNull { ref_id }
        | RegType::PtrToOwnedKptrOrNull { ref_id, .. }
        | RegType::PtrToTaskOrNull { ref_id }
        | RegType::PtrToMapKptrOrNull { ref_id, .. } => ref_id,
        // PtrToBtfIdOrNull only carries a ref_id when minted by an
        // ACQUIRE-flagged kfunc returning `RetKind::PtrToBtfIdNamed`
        // (`bpf_get_task_exe_file`, `bpf_lookup_user_key`, …). The plain
        // entry-arg / decl-tag path uses `ref_id: None` and falls
        // through to the catch-all return below — no release needed on
        // the null branch.
        RegType::PtrToBtfIdOrNull { ref_id: Some(rid), .. } => Some(rid),
        _ => return,
    };

    // Always refine the originating register itself; cross-register and
    // stack-slot propagation is gated on a shared, *concrete* ref_id
    // (`same_acquired_pointer` returns false when both ids are None —
    // see comment there).
    if is_non_null {
        if let Some(promoted) = reg_type.to_non_null() {
            state.types.set(reg, promoted);
        }
        for r in Reg::ALL {
            if r == reg {
                continue;
            }
            let ty = state.types.get(r);
            if same_acquired_pointer(&reg_type, &ty) {
                state.types.set(r, ty.to_non_null().unwrap());
            }
        }
        promote_stack_slots_all_frames(
            state,
            |ty| same_acquired_pointer(&reg_type, ty),
            |ty| ty.to_non_null().unwrap_or(RegType::ScalarValue),
        );
    } else {
        if let Some(ref_id) = target_ref_id {
            state.release_ref(ref_id);
        }
        state.types.set(reg, RegType::ScalarValue);
        for r in Reg::ALL {
            if r == reg {
                continue;
            }
            let ty = state.types.get(r);
            if same_acquired_pointer(&reg_type, &ty) {
                state.types.set(r, RegType::ScalarValue);
                // The pointer was just proved null on this branch.
                // Tighten the linked register's bounds to [0, 0] so
                // subsequent null-tests can refute the impossible
                // non-zero branch. Without this, only the type is
                // demoted; bounds stay wide (whatever was captured
                // at acquisition time) and a later `if linked == 0`
                // fails to prove always-taken.
                state.domain.assign_imm(r, 0);
                state.set_tnum(r, crate::domains::tnum::Tnum::constant(0));
            }
        }
        // Stack slots that aliased the acquired ref are now NULL too.
        // Demote type AND tighten bounds + tnum to constant 0; without
        // the bounds refinement, a later spill+fill of a slot that
        // held an `OwnedKptrOrNull` with a wide capture range produces
        // a wide-interval ScalarValue, and a downstream `if X == 0`
        // explores an impossible non-zero branch — that's the leak
        // that caused the FALSE-REJECT in
        // `rbtree::rbtree_add_and_remove_array` (err_out path from
        // `pc=23` would reach the `bpf_obj_drop` at pc=184 with R1 as
        // wide-bound ScalarValue).
        for frame in state.frames.iter_mut() {
            let offsets: Vec<i16> = frame.stack.slot_offsets();
            for k in offsets {
                let ty = frame.stack.get_slot_type(k);
                if same_acquired_pointer(&reg_type, &ty)
                    && let Some(slot) = frame.stack.get_slot_mut(k) {
                        slot.reg_type = RegType::ScalarValue;
                        slot.bounds = crate::analysis::machine::stack_state::ScalarBounds {
                            min: 0,
                            max: 0,
                        };
                        slot.tnum = crate::domains::tnum::Tnum::constant(0);
                    }
            }
        }
    }
}
