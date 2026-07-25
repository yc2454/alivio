// BCF map-region refinement driver (kernel bcf_refine for map accesses):
// legacy + replay-rebuild goal variants, bundle push, children_unsafe
// marking. Called from memory/map.rs bounds-check reject sites.

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;

/// Helper: try the BCF map-region refinement and stash the proof on
/// `env.bcf_proofs` on success. Returns `true` if the rejection should
/// be suppressed. Mirrors `try_bcf_refine_stack` in [`memory::stack`].
pub(crate) fn try_bcf_refine_map(
    env: &mut VerifierEnv,
    state: &State,
    base: Reg,
    insn_off: i64,
    size: i64,
    map_limit: i64,
) -> bool {
    if state.bcf.is_none() {
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
    let ptr_is_const = match state
        .domain
        .as_interval()
        .and_then(|i| i.get_ptr_offset(base))
    {
        Some(ptr_off) => ptr_off.min_offset() == ptr_off.max_offset(),
        None => true,
    };
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
    let landed = state.history_idx.and_then(|hidx| {
        crate::analysis::flow::precision::bcf_suffix_base_pc_and_cache_id(
            env,
            hidx,
            state.parent_cache_id,
            &target_regs,
        )
    });
    let base_pc = landed.map(|(pc, _)| pc);
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
    if !env.replay_mode
        && let Some((_, cid)) = landed
    {
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
            let mut cur = env
                .state_by_cache_id(cid)
                .and_then(|(_, s)| s.parent_cache_id);
            while let Some(c) = cur {
                if rung_cids.len() >= 12 {
                    break;
                }
                rung_cids.push(c);
                cur = env
                    .state_by_cache_id(c)
                    .and_then(|(_, s)| s.parent_cache_id);
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
                cur = env
                    .state_by_cache_id(c)
                    .and_then(|(_, s)| s.parent_cache_id);
            }
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
                    env,
                    *rcid,
                    anchor_at_parent,
                    share_slot_vars,
                    crossing,
                    None,
                ) && let Some(ok) = crate::refinement::refine_map::try_refine_map_access(
                    &rst,
                    base,
                    insn_off,
                    size,
                    map_limit,
                    size_reg,
                    None,
                    Some(&known),
                ) {
                    known.insert(crate::refinement::canonical_hash::hash_expr(
                        ok.goal_root,
                        &ok.sym.exprs,
                    ));
                    replay_variants.push(ok);
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
                        env,
                        deep_cid,
                        false,
                        true,
                        Some(k),
                        Some(cut_pc),
                    ) && let Some(ok) = crate::refinement::refine_map::try_refine_map_access(
                        &rst,
                        base,
                        insn_off,
                        size,
                        map_limit,
                        size_reg,
                        None,
                        Some(&known),
                    ) {
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
    let attempts: Vec<(bool, _)> = legacy_ok
        .into_iter()
        .map(|o| (false, o))
        .chain(replay_variants.into_iter().map(|o| (true, o)))
        .collect();
    if attempts.is_empty() {
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
                "refine_map",
                state.pc,
                -1,
                -1,
                entry.cond_hash,
                env.bcf_proofs
                    .iter()
                    .any(|e| e.cond_hash == entry.cond_hash),
            );
        }
        // Legacy entries push unconditionally (pre-existing behavior — bundle
        // bytes for every currently-passing object stay identical). The
        // replay variant is ADDITIVE and dedupes by canonical hash: on
        // straight-line suffixes it coincides with the legacy goal and must
        // not double the bundle.
        if !is_replay_variant
            || !env
                .bcf_proofs
                .iter()
                .any(|e| e.cond_hash == entry.cond_hash)
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
    crate::analysis::flow::pruning::cache::mark_path_children_unsafe(
        env,
        state,
        landed.map(|(_, cid)| cid),
    );
    true
}
