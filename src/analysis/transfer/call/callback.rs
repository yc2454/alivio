// src/analysis/transfer/call/callback.rs

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::error::VerificationError;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use crate::analysis::transfer::types::{update_call_rel_types, update_call_types};
use crate::common::constants;
use crate::domains::tnum::Tnum;

use super::transfer::apply_return_bounds;

/// True when `helper` takes a callback pointer argument.
pub(super) fn is_callback_helper(helper: u32) -> bool {
    matches!(
        helper,
        constants::BPF_LOOP
            | constants::BPF_FOR_EACH_MAP_ELEM
            | constants::BPF_TIMER_SET_CALLBACK
            | constants::BPF_USER_RINGBUF_DRAIN
            | constants::BPF_FIND_VMA
    )
}

/// Which register holds the callback pointer for `helper`.
fn callback_arg_reg(helper: u32) -> Reg {
    match helper {
        constants::BPF_LOOP => Reg::R2,
        constants::BPF_FOR_EACH_MAP_ELEM => Reg::R2,
        constants::BPF_TIMER_SET_CALLBACK => Reg::R2,
        // bpf_user_ringbuf_drain(map, callback, ctx, flags)
        constants::BPF_USER_RINGBUF_DRAIN => Reg::R2,
        // bpf_find_vma(task, addr, callback, callback_ctx, flags)
        constants::BPF_FIND_VMA => Reg::R3,
        _ => unreachable!(),
    }
}

/// Transfer for callback-taking helpers. Emits the skip successor (normal
/// helper post-state at pc+1) and the enter-callback successor (pushes a
/// callback frame at subprog_pc with typed args). See `is_callback_helper`.
pub(super) fn transfer_callback_helper(
    env: &mut VerifierEnv,
    state: State,
    in_types: &crate::analysis::machine::reg_types::TypeState,
    helper: u32,
) -> Vec<State> {
    let pc = state.pc;
    let cb_reg = callback_arg_reg(helper);
    let RegType::PtrToCallback { subprog_pc } = state.types.get(cb_reg) else {
        env.fail(VerificationError::InvalidArgType { pc, reg: cb_reg });
        return vec![];
    };
    let cb_entry = subprog_pc as usize;

    // bpf_timer_set_callback must be registered with no held locks
    // and no unreleased refs — the callback runs asynchronously, so any
    // state the verifier is still tracking on the caller frame would be
    // leaked. (Other callback helpers are synchronous and rely on the
    // generic active-lock check in `transfer_call` above.)
    if helper == constants::BPF_TIMER_SET_CALLBACK
        && (state.has_active_lock() || state.has_unreleased_refs())
    {
        env.fail(VerificationError::InvalidArgType { pc, reg: cb_reg });
        return vec![];
    }

    // Successor A: skip the callback and emit the helper's post-state.
    let mut skip_state = state.clone();
    // Kernel-pessimism for sync callbacks: the callback could have
    // re-initialized any dynptr reachable through its ctx arg, which
    // invalidates slices tagged with the old `dynptr_id`. Mirrors the
    // `bpf_for_each_reg_in_vstate` sweep done by
    // `destroy_if_dynptr_stack_slot` (verifier.c v6.15 L913-919) once
    // the kernel determines the ctx may alias a dynptr stack slot.
    // Without this, `invalid_data_slices` (dynptr_fail.c) would accept
    // a `*slice = 1` after `bpf_loop(.., &ptr, 0)`.
    let cb_ctx_reg = match helper {
        constants::BPF_LOOP
        | constants::BPF_FOR_EACH_MAP_ELEM
        | constants::BPF_USER_RINGBUF_DRAIN => Some(Reg::R3),
        constants::BPF_FIND_VMA => Some(Reg::R4),
        _ => None,
    };
    // Only invalidate when the cb body could plausibly destroy (re-init
    // or overwrite) the dynptr — kernel `destroy_if_dynptr_stack_slot`
    // fires on real init operations OR direct stack writes that
    // overlap a dynptr slot. Without this gate we FR
    // dynptr_success::test_ringbuf (cb just reads via bpf_dynptr_data).
    // The pessimism is still required for:
    //   - `invalid_data_slices`: cb writes `*data = 123` to the ctx arg
    //     (the &dynptr stack address), partially destroying it →
    //     `cb_body_store_offsets` is non-empty.
    //   - cbs that call dynptr-init kfuncs → `cb_body_can_reinit_dynptr`.
    let cb_could_reinit = env.cb_body_can_reinit_dynptr.contains(&cb_entry)
        || env
            .cb_body_store_offsets
            .get(&cb_entry)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
    if cb_could_reinit
        && let Some(ctx_reg) = cb_ctx_reg
        && let RegType::PtrToStack { frame_level } = skip_state.types.get(ctx_reg)
        && let Some(off) = skip_state.domain.get_distance_fixed(ctx_reg, Reg::R10)
        && let Ok(base_off) = i16::try_from(off)
    {
        let touched = skip_state
            .stack_at(frame_level)
            .dynptr_pairs_touched_by_write(base_off as i64, 16);
        if !touched.is_empty() {
            let stack = skip_state.stack_at_mut(frame_level);
            for (b, _) in &touched {
                stack.stack_clear_dynptr(*b);
                stack.stack_clear_dynptr(*b + 8);
            }
            for (_, vid) in &touched {
                skip_state.invalidate_dynptr_slices(*vid);
            }
        }
    }
    update_call_types(env, in_types, &mut skip_state, helper);
    apply_return_bounds(&mut skip_state, helper);
    if skip_state.types.get(Reg::R0) == RegType::ScalarValue
        && skip_state.get_tnum(Reg::R0).is_unknown()
    {
        skip_state.alloc_scalar_id(Reg::R0);
    } else {
        skip_state.clear_scalar_id(Reg::R0);
    }
    for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
        skip_state.domain.forget(r);
        skip_state.set_tnum(r, Tnum::unknown());
        skip_state.clear_scalar_id(r);
    }
    skip_state.pc = pc + 1;

    // Successor B: enter the callback with a fresh frame. Bail with the
    // skip state only if we're already at the kernel's max call depth.
    if state.num_frames() >= 8 {
        return vec![skip_state];
    }

    // Decide whether cb iteration could run ≥ 2 times — drives the widen
    // decision on cb-Exit propagation. Mirrors kernel's
    // `widen_imprecise_scalars` only triggering when find_prev_entry
    // returns a previous iteration to compare against (verifier.c v6.15
    // L10903–10920).
    let cb_should_widen = match helper {
        constants::BPF_LOOP => {
            // nr_loops is caller's R1. If max ≤ 1, only one iter possible
            // (concrete merge). Else widen.
            let (_, hi) = state.domain.get_interval(Reg::R1);
            hi > 1
        }
        // bpf_for_each_map_elem / user_ringbuf_drain / find_vma: variable
        // count (depends on map size / ringbuf entries / vma matches).
        // The kernel's iteration logic walks ≥ 2 entries when the cb's
        // exit-state isn't iter-stable, so widen scalar effects across
        // iterations — matches the `unsafe_find_vma` reject pattern in
        // verifier_iterating_callbacks.c.
        constants::BPF_FOR_EACH_MAP_ELEM
        | constants::BPF_USER_RINGBUF_DRAIN
        | constants::BPF_FIND_VMA => true,
        _ => false,
    };

    // Pre-push: capture caller's ctx-arg register so we can install it
    // as the cb's ctx parameter after the frame push (which clears the
    // caller-side regs). For sync callbacks the kernel passes the
    // caller's ctx pointer to a specific cb arg register
    // (`set_loop_callback_state` etc., verifier.c v6.15 ~L10685+).
    // Without this, the cb body's first read of ctx hits "R2 !read_ok".
    // Build the full caller→cb propagation list. Each entry is
    // `(cb_dst, caller_src_reg, caller_src_type, caller_src_tnum)`.
    // Mirrors kernel `set_*_callback_state` (verifier.c v6.15 ~L10685+):
    // the cb arg IS the caller's pointer/value, unchanged. The domain
    // half is copied via `assign_reg(cb_dst, caller_src_reg)` BEFORE the
    // generic clear (sources still intact in the freshly-cloned cb
    // domain) so a `PtrToStack`/`PtrToMapValue`/… ctx arg keeps its
    // frame-relative offset — exactly what the static-subprog
    // `push_frame` path already does (it never clobbers arg regs).
    // A `forget`+scalar `assign_interval` would drop the offset, so
    // a cb deref of a caller-stack ctx pointer became "Stack out of
    // bounds (Unknown offset)". `snap`'s scalar interval is unused now
    // (assign_reg supersedes it); type+tnum still carried explicitly.
    let mut ctx_propagations: Vec<(Reg, Reg, RegType, Tnum)> = Vec::new();
    let snap = |st: &State, r: Reg| (st.types.get(r), st.get_tnum(r));

    // bpf_timer_set_callback: caller's R1 = `&map_value->timer`
    // (PtrToMapValue carrying the timer's owning map_idx). Captured here
    // so the cb-arg typing block below can install
    // R1=PtrToMapObject{map_idx}, R2/R3=PtrToMapValue{map_idx} once
    // `state` has been moved into `cb_state`.
    let caller_r1_for_timer_cb: Option<usize> =
        if helper == constants::BPF_TIMER_SET_CALLBACK {
            match state.types.get(Reg::R1) {
                RegType::PtrToMapValue { map_idx, .. } => Some(map_idx),
                _ => None,
            }
        } else {
            None
        };
    match helper {
        // bpf_loop(nr_loops, cb, ctx, flags) → cb(idx, ctx); R1=idx (scalar, set later), ctx → R2.
        constants::BPF_LOOP
        // bpf_user_ringbuf_drain(map, cb, ctx, flags) → cb(dynptr, ctx); R1=dynptr (left NotInit; few tests deref), ctx → R2.
        | constants::BPF_USER_RINGBUF_DRAIN => {
            let (ty, tn) = snap(&state, Reg::R3);
            ctx_propagations.push((Reg::R2, Reg::R3, ty, tn));
        }
        // bpf_for_each_map_elem(map, cb, ctx, flags) → cb(map, key, val, ctx);
        // R1=caller's R1 (the map ptr); R2=PTR_TO_MAP_KEY, R3=PTR_TO_MAP_VALUE
        // (we don't track those distinctly — use a lax BTF-typed pointer that
        // permits generic loads, mirroring the timer-cb fallback); R4=ctx.
        constants::BPF_FOR_EACH_MAP_ELEM => {
            let (ty1, tn1) = snap(&state, Reg::R1);
            ctx_propagations.push((Reg::R1, Reg::R1, ty1, tn1));
            let (ty3, tn3) = snap(&state, Reg::R3);
            ctx_propagations.push((Reg::R4, Reg::R3, ty3, tn3));
        }
        // bpf_find_vma(task, addr, cb, ctx, flags) → cb(task, vma, ctx);
        // R1=caller's R1 (task), R2=PTR_TO_BTF_ID{vm_area_struct}, R3=ctx.
        constants::BPF_FIND_VMA => {
            let (ty1, tn1) = snap(&state, Reg::R1);
            ctx_propagations.push((Reg::R1, Reg::R1, ty1, tn1));
            let (ty4, tn4) = snap(&state, Reg::R4);
            ctx_propagations.push((Reg::R3, Reg::R4, ty4, tn4));
        }
        _ => {}
    }

    // Caller's ctx-arg base offset (relative to caller's R10). Captured
    // before the move into cb_state below; needed to translate cb-body
    // store offsets into caller-frame stack offsets for the widening
    // propagation set.
    let caller_ctx_base_off: Option<i64> = {
        let caller_ctx_reg = match helper {
            constants::BPF_LOOP
            | constants::BPF_USER_RINGBUF_DRAIN
            | constants::BPF_FOR_EACH_MAP_ELEM => Some(Reg::R3),
            constants::BPF_FIND_VMA => Some(Reg::R4),
            _ => None,
        };
        caller_ctx_reg.and_then(|r| state.domain.get_distance_fixed(r, Reg::R10))
    };

    let mut cb_state = state;
    let caller_level_idx = cb_state.current_frame_level();
    let caller_stack_snapshot =
        cb_state.frames.get(caller_level_idx).stack.clone();
    cb_state.push_callback_frame(pc + 1, helper);
    cb_state.frames.current_mut().set_cb_propagation(
        caller_stack_snapshot,
        caller_level_idx.index(),
        cb_should_widen,
    );
    // Pre-computed cb-body store offsets (relative to the cb's ctx-arg
    // pointer). Translate to caller-frame offsets by adding the
    // caller's ctx-arg base offset (distance from caller's R10), then
    // stash on the cb frame so cb_exit_propagate can invalidate them
    // on widening.
    if let (Some(offsets), Some(base)) = (
        env.cb_body_store_offsets.get(&cb_entry),
        caller_ctx_base_off,
    ) {
        let translated: Vec<i16> = offsets
            .iter()
            .filter_map(|&cb_off| {
                let total = base.checked_add(cb_off as i64)?;
                i16::try_from(total).ok()
            })
            .collect();
        cb_state
            .frames
            .current_mut()
            .set_cb_writeable_caller_offsets(translated);
    }
    update_call_rel_types(&mut cb_state);
    cb_state.domain.clear_packet_size_bounds();

    // Domain half of caller→cb propagation. Copy the FULL per-reg
    // domain state (scalar bounds + ptr_offset) caller_src → cb_dst
    // BEFORE the generic clear, while the sources are still intact in
    // the freshly-cloned cb domain. This is exactly what the
    // static-subprog `push_frame` path does implicitly (it never
    // clobbers arg regs), and is required for a `PtrToStack` /
    // `PtrToMapValue` ctx arg to keep its frame-relative offset so the
    // cb body can dereference it (`check_stack_access` resolves it via
    // the carried `frame_level`).
    let prop_dsts: std::collections::HashSet<Reg> =
        ctx_propagations.iter().map(|&(d, ..)| d).collect();
    for &(dst, src, ..) in ctx_propagations.iter() {
        cb_state.domain.assign_reg(dst, src);
    }

    // Minimal arg typing: clear R1..R5 EXCEPT the propagation dsts
    // (whose domain state was just copied above), then re-install
    // per-helper. R1 for bpf_loop is the iteration index (scalar).
    // Other helpers' R1 and additional pointer args are installed via
    // `ctx_propagations` and the static-typed table below; remaining
    // regs stay NotInit so callbacks that dereference them REJECT.
    for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
        if prop_dsts.contains(&r) {
            continue;
        }
        cb_state.types.set(r, RegType::NotInit);
        cb_state.domain.forget(r);
        cb_state.set_tnum(r, Tnum::unknown());
        cb_state.clear_scalar_id(r);
    }
    // bpf_loop only: R1 = iteration index (scalar). Other helpers
    // install R1 via ctx_propagations.
    if helper == constants::BPF_LOOP {
        cb_state.types.set(Reg::R1, RegType::ScalarValue);
        cb_state.domain.forget(Reg::R1);
        cb_state.set_tnum(Reg::R1, Tnum::unknown());
        cb_state.alloc_scalar_id(Reg::R1);
    }

    // Install propagated arg TYPES + tnums (the domain half was
    // already copied via `assign_reg` above, preserving ptr_offset).
    for (dst, _src, ty, tnum) in ctx_propagations.drain(..) {
        cb_state.types.set(dst, ty);
        cb_state.set_tnum(dst, tnum);
        cb_state.clear_scalar_id(dst);
    }

    // Static-typed cb args (kernel `set_*_callback_state` PTR_TO_BTF_ID /
    // PTR_TO_MAP_KEY / PTR_TO_MAP_VALUE entries). We don't track
    // PTR_TO_MAP_KEY / VALUE distinctly — approximate with a lax
    // BTF-typed pointer that admits generic loads (existing timer-cb
    // pattern). Tighter typing is future work.
    {
        use crate::analysis::machine::reg_types::PtrFlags;
        let unknown_btf = || RegType::PtrToBtfId {
            type_name: "unknown",
            flags: PtrFlags::TRUSTED,
            ref_id: None,
        };
        match helper {
            // cb(map, key, val, ctx) — R2=key, R3=val. Kernel sets
            // R2=PTR_TO_MAP_KEY, R3=PTR_TO_MAP_VALUE (verifier.c
            // `set_map_elem_callback_state`). We don't track PTR_TO_MAP_KEY
            // distinctly; approximate both as `PtrToMapValue { map_idx }`
            // pulled from caller's R1 (the map ptr passed to
            // bpf_for_each_map_elem). This admits the cb body's
            // `bpf_map_*_elem(map, key, val, ...)` calls — validators
            // delegate through `validate_readable_mem` which accepts
            // PtrToMapValue and bound-checks against the map's value_size.
            //
            // Limitation: when `key_size > value_size` (rare hash maps
            // with large keys / small values), the read of `key_size`
            // bytes from a PtrToMapValue with mem_size=value_size
            // under-reads — this would FA. Both failing selftests
            // (`for_each_hash_map_elem`, `for_each_hash_modify`) have
            // key_size <= value_size, so the approximation is safe for
            // the closures. Tighter typing (real PTR_TO_MAP_KEY) is
            // future work.
            constants::BPF_FOR_EACH_MAP_ELEM => {
                // R1 was just installed via ctx_propagations from
                // caller's R1 (the map ptr passed to
                // bpf_for_each_map_elem) — read it back here to derive
                // map_idx for the cb's R2/R3 typing.
                let caller_map_idx = match cb_state.types.get(Reg::R1) {
                    RegType::PtrToMapObject { map_idx } => Some(map_idx),
                    _ => None,
                };
                for r in [Reg::R2, Reg::R3] {
                    // Kernel `set_map_elem_callback_state` stamps R2 as
                    // PTR_TO_MAP_KEY (read-only) and R3 as
                    // PTR_TO_MAP_VALUE (writable). We don't track
                    // PTR_TO_MAP_KEY distinctly — approximate with
                    // PtrToMapValue but mark `rdonly: true` on R2 so
                    // helper write-paths reject. Closes
                    // for_each_map_elem_write_key::test_map_key_write
                    // (`bpf_get_current_comm(key, sizeof(*key))`).
                    let ty = match caller_map_idx {
                        Some(map_idx) => RegType::PtrToMapValue {
                            id: crate::analysis::machine::reg_types::new_ptr_id(),
                            offset: Some(0),
                            map_idx,
                            map_uid: None,
                            rdonly: r == Reg::R2,
                        },
                        None => unknown_btf(),
                    };
                    cb_state.types.set(r, ty);
                    cb_state.domain.forget(r);
                    if caller_map_idx.is_some() {
                        cb_state.domain.init_map_value_ptr(r);
                    }
                    cb_state.set_tnum(r, Tnum::unknown());
                    cb_state.clear_scalar_id(r);
                }
            }
            // cb(struct bpf_dynptr *dynptr, void *ctx) — kernel sets
            // R1 = PTR_TO_DYNPTR | DYNPTR_TYPE_USER | MEM_RDONLY
            // (`set_user_ringbuf_callback_state`, verifier.c v6.15
            // ~L10800). PtrToDynptr accepts dynptr consumer kfuncs
            // (`bpf_dynptr_data`, `_read`); load/store on it falls
            // through to UnsafeGenericLoad/Store ("invalid mem access
            // 'dynptr_ptr'"); ALU demotes to scalar (kernel rejects
            // "dereference of modified dynptr_ptr ptr").
            constants::BPF_USER_RINGBUF_DRAIN => {
                use crate::analysis::machine::stack_state::DynptrKind;
                cb_state.types.set(
                    Reg::R1,
                    RegType::PtrToDynptr {
                        kind: DynptrKind::User,
                        rdonly: true,
                    },
                );
                cb_state.domain.forget(Reg::R1);
                cb_state.set_tnum(Reg::R1, Tnum::unknown());
                cb_state.clear_scalar_id(Reg::R1);
            }
            // cb(task, vma, ctx) — R2 = PTR_TO_BTF_ID{vm_area_struct, TRUSTED}.
            constants::BPF_FIND_VMA => {
                cb_state.types.set(
                    Reg::R2,
                    RegType::PtrToBtfId {
                        type_name: "vm_area_struct",
                        flags: PtrFlags::TRUSTED,
                        ref_id: None,
                    },
                );
                cb_state.domain.forget(Reg::R2);
                cb_state.set_tnum(Reg::R2, Tnum::unknown());
                cb_state.clear_scalar_id(Reg::R2);
            }
            _ => {}
        }
    }

    // Timer cb signature is `(struct bpf_map *, void *key, void *value)`
    // — kernel `set_timer_callback_state` (verifier.c ~L10685, v6.15)
    // sets R1=CONST_PTR_TO_MAP, R2=PTR_TO_MAP_KEY, R3=PTR_TO_MAP_VALUE
    // off the timer's owning map. Caller's R1 is `&map_value->timer`
    // (PtrToMapValue with the timer's owning map_idx); pull map_idx
    // from there. Required so the cb body's `bpf_timer_start(timer, ...)`
    // sees R3 = PtrToMapValue{map_idx, offset:0} and the helper's
    // Timer-field validator can walk the value type — without this
    // R3 falls back to PtrToBtfId{type_name:"unknown"} and the
    // validator rejects (timer.c::race).
    if helper == constants::BPF_TIMER_SET_CALLBACK {
        let timer_map_idx = caller_r1_for_timer_cb;
        use crate::analysis::machine::reg_types::PtrFlags;
        let unknown_btf = || RegType::PtrToBtfId {
            type_name: "unknown",
            flags: PtrFlags::TRUSTED,
            ref_id: None,
        };
        // R1 = CONST_PTR_TO_MAP (the timer's owning map).
        let r1_ty = match timer_map_idx {
            Some(map_idx) => RegType::PtrToMapObject { map_idx },
            None => unknown_btf(),
        };
        cb_state.types.set(Reg::R1, r1_ty);
        cb_state.domain.forget(Reg::R1);
        cb_state.set_tnum(Reg::R1, Tnum::unknown());
        cb_state.clear_scalar_id(Reg::R1);
        // R2 = key. Kernel sets PTR_TO_MAP_KEY (size=key_size). We don't
        // track PTR_TO_MAP_KEY distinctly; the lax BtfId{unknown}
        // already accepts the deref-and-forward pattern that
        // verifier_private_stack.c::private_stack_async_callback_2
        // exercises (`subprog1(key) → tmp[0] = *val → subprog2(tmp)`),
        // so don't tighten this slot — typing it as PtrToMapValue
        // bound-checks against value_size which forces a different
        // (incorrect) load-size policy through the int-deref path.
        cb_state.types.set(Reg::R2, unknown_btf());
        cb_state.domain.forget(Reg::R2);
        cb_state.set_tnum(Reg::R2, Tnum::unknown());
        cb_state.clear_scalar_id(Reg::R2);
        // R3 = value. Type as PtrToMapValue{map_idx, offset:0} so the
        // cb body's `bpf_timer_*(value, ...)` Timer-field validator
        // can walk the map's value BTF (timer.c::race_timer_callback's
        // `bpf_timer_start(timer)` where `timer` is the cb's R3 arg).
        let r3_ty = match timer_map_idx {
            Some(map_idx) => RegType::PtrToMapValue {
                id: crate::analysis::machine::reg_types::new_ptr_id(),
                offset: Some(0),
                map_idx,
                map_uid: None,
                rdonly: false,
            },
            None => unknown_btf(),
        };
        cb_state.types.set(Reg::R3, r3_ty);
        cb_state.domain.forget(Reg::R3);
        if timer_map_idx.is_some() {
            cb_state.domain.init_map_value_ptr(Reg::R3);
        }
        cb_state.set_tnum(Reg::R3, Tnum::unknown());
        cb_state.clear_scalar_id(Reg::R3);
    }

    cb_state.pc = cb_entry;

    vec![skip_state, cb_state]
}

pub(super) fn allowed_while_in_active_lock(helper: u32) -> bool {
    !matches!(helper, constants::BPF_GET_PRANDOM_U32)
}
