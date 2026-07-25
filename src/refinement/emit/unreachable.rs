// Path-unreachable goal emission driver: natural goal + replay family +
// ancestor/reg-filtered variants, bundle push, children_unsafe marking.

use super::replay::try_prove_unreachable_via_replay;
use super::{unreachable_base_pc, unreachable_target_regs};
use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::state::State;

/// Emission census (ALIVIO_BCF_CENSUS=1, diagnosis-only): one line per bundle
/// push ATTEMPT, tagged with the emission-class that produced the goal, so the
/// per-class hash sets can be intersected offline against a kernel load's
/// queried set ([ZK try_discharge] dmesg lines). `depth` = ancestor-chain
/// depth (-1 where n/a), `rung` = replay reset-ladder If pc (-1 = plain).
pub(crate) fn census_log(
    class: &str,
    reject_pc: usize,
    depth: i32,
    rung: i32,
    hash: u64,
    dup: bool,
) {
    if std::env::var("ALIVIO_BCF_CENSUS").ok().as_deref() == Some("1") {
        eprintln!(
            "[census] pc={} class={} depth={} rung={} hash={:016x} dup={}",
            reject_pc, class, depth, rung, hash, dup as u32
        );
    }
}

/// Attempt path-unreachable speculation on a alivio-infeasible state and
/// push the resulting `kind=BCF_BUNDLE_KIND_UNREACHABLE` bundle entry on
/// success. Returns `true` iff an entry was emitted. Mirrors the pattern
/// in `try_bcf_refine_stack` / `try_bcf_refine_map`.
///
/// Called from two places: (a) the zone-only branch-side eager
/// speculation here, and (b) reactively from the generic-load (scalar)
/// rejection site (`memory::access`), mirroring the kernel's
/// `bcf_prove_unreachable` at verifier.c:8224→8255.
pub(crate) fn try_emit_path_unreachable_entry(env: &mut VerifierEnv, state: &State) -> bool {
    use crate::refinement::bundle::{BCF_BUNDLE_KIND_UNREACHABLE, RefineEntry};
    use crate::refinement::refine_unreachable::try_prove_unreachable;
    use log::info;

    // No re-entrant discharge during a replay: the replay re-executes a
    // suffix only to rebuild the path condition; it must not itself attempt
    // to discharge (which would recurse and pollute the bundle).
    if (env.replay_mode || state.bcf.is_none())
        && std::env::var("ALIVIO_DUMP_DISCHARGE").ok().as_deref() == Some("1")
    {
        eprintln!(
            "[disc-skip] reject@pc={} replay={} bcf_none={} parent_cid={:?}",
            state.pc,
            env.replay_mode,
            state.bcf.is_none(),
            state.parent_cache_id
        );
    }
    if env.replay_mode {
        return false;
    }
    if state.bcf.is_none() {
        return false;
    }
    // FAITHFUL base. The kernel's ONE `base` from
    // backtrack_states gives BOTH the goal anchor (`base->insn_idx`, the
    // replay start) AND the marking bound (parents[] = the chain up to base).
    // `base_pc` = `base->insn_idx` (anchor, for the prove/goal calls). The
    // marking below uses `base_cid_dbg` (the base cache_id) to mark exactly
    // the `parents[]` chain — no split, no bcidx/EXCLUDE_BASE pc-window.
    let base_pc = unreachable_base_pc(env, state);
    // Mirror kernel's `vstate->last_insn_idx` retrieval at bcf_track
    // replay start: look up the prev_insn PC of the cached state AT
    // base_pc (the cache the suffix walk landed on, not the immediate
    // parent_cache_id of cur — they can differ). The filter uses this
    // to identify the immediate-predecessor branch cond (the kernel's
    // record_path_cond push at insn=base_pc, verifier.c:21117).
    let (prev_insn_pc, base_cid_dbg) = {
        // Shared target mask — IDENTICAL to unreachable_base_pc via the
        // common helper. A drift here empties the cache-id walk at a
        // different insn than the pc walk, leaving base_cid=None and
        // skipping the faithful REPLAY.
        let hidx = env.current_step_idx.or(state.history_idx);
        let targets = unreachable_target_regs(env, state, hidx);
        let landed = hidx.and_then(|hidx| {
            crate::analysis::flow::precision::bcf_suffix_base_pc_and_cache_id(
                env,
                hidx,
                state.parent_cache_id,
                &targets,
            )
        });
        // Use only the immediate cache the suffix walker landed on (no
        // chain-skip through parent_cache_id): the kernel-faithful
        // prev_insn is the landed cache's own, which need not be a
        // scalar branch.
        let pp = landed.and_then(|(_base_pc, base_cid)| env.cached_prev_insn_pc(base_cid));
        let cid = landed.map(|(_, cid)| cid);
        (pp, cid)
    };
    if std::env::var("ALIVIO_DUMP_DISCHARGE").ok().as_deref() == Some("1") {
        eprintln!(
            "[disc] reject@pc={} base_pc={:?} prev_insn_pc={:?} parent_cid={:?} base_cid={:?}",
            state.pc, base_pc, prev_insn_pc, state.parent_cache_id, base_cid_dbg
        );
    }
    // LEAN EMISSION — THE DEFAULT: emit the replay family (replay_base all
    // rungs + ancestor replays depth 0-1) and fall through to the full
    // reconstruction fan-out ONLY for rejects where the replay family
    // produced nothing (base-less full-path goals). Control flow, the cvc5
    // prove of the natural goal (gates the return value), and
    // mark_path_children_unsafe are IDENTICAL to the fat path; only bundle
    // pushes differ. The skipped classes' code below is kept: it IS the
    // base-less fallback path.
    let lean = true;
    // REPLAY = faithful base→reject re-execution (kernel bcf_track mirror);
    // ADDITIVE alongside the reconstruction discharge (merge dedups by
    // cond_hash).
    let mut replay_goals_produced: usize = 0;
    {
        if std::env::var("ALIVIO_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1") {
            eprintln!(
                "[replay] CALL reject@pc={} base_cid={:?}",
                state.pc, base_cid_dbg
            );
        }
        if let Some(cid) = base_cid_dbg {
            for (rung, rok) in try_prove_unreachable_via_replay(env, state, cid) {
                let rentry = RefineEntry::new(
                    rok.goal_root,
                    rok.sym.exprs,
                    rok.proof_bytes,
                    BCF_BUNDLE_KIND_UNREACHABLE,
                );
                if std::env::var("ALIVIO_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1") {
                    eprintln!(
                        "[replay] HASH reject@pc={} hash={:016x}",
                        state.pc, rentry.cond_hash
                    );
                }
                replay_goals_produced += 1;
                let dup = env
                    .bcf_proofs
                    .iter()
                    .any(|e| e.cond_hash == rentry.cond_hash);
                census_log("replay_base", state.pc, -1, rung, rentry.cond_hash, dup);
                if dup {
                    continue;
                }
                info!(target: "app",
                    "[bcf] REPLAY path-unreachable: proof {} bytes (hash {:016x})",
                    rentry.proof_bytes.len(), rentry.cond_hash);
                env.bcf_proofs.push(rentry);
            }
        }
    }
    let Some(ok) = try_prove_unreachable(state, base_pc, prev_insn_pc) else {
        // Kernel bcf_refine marks parents[] children_unsafe UNCONDITIONALLY
        // at its tail (verifier.c:24822) — after discharge FOUND, MISS, or
        // any goal/proof-formation failure alike. Returning here without
        // marking would leave the reject's ancestor chain prune-safe, so
        // later arrivals would subsume on it and their own rejects never
        // happen. (The replay-family pushes above have already run by this
        // point; the kernel's parallel is goals built, natural proof
        // unavailable.)
        crate::analysis::flow::pruning::cache::mark_path_children_unsafe(env, state, base_cid_dbg);
        return false;
    };
    let entry = RefineEntry::new(
        ok.goal_root,
        ok.sym.exprs,
        ok.proof_bytes,
        BCF_BUNDLE_KIND_UNREACHABLE,
    );
    info!(
        target: "app",
        "[bcf] path-unreachable speculation: cvc5 proof {} bytes (hash {:016x})",
        entry.proof_bytes.len(),
        entry.cond_hash
    );
    if std::env::var("ALIVIO_BCF_CENSUS").ok().as_deref() == Some("1") {
        census_log(
            "natural",
            state.pc,
            -1,
            -1,
            entry.cond_hash,
            env.bcf_proofs
                .iter()
                .any(|e| e.cond_hash == entry.cond_hash),
        );
    }
    if lean {
        // Lean mode: the natural prove above still gates the return value
        // (and thus parent marking) exactly as before, but its entry and all
        // reconstruction twins below stay out of the bundle; the ancestor
        // walk runs only the shallow replays (depth <= 1 — the kernel's
        // base can land up to two cache-hops below the walker).
        // Aliased-VAR (no-rewrite) reconstruction twin at the natural
        // base: the kernel queries via the aliased form on some programs,
        // a shape the replay never produces.
        if let Some(ok_no_rw) =
            crate::refinement::refine_unreachable::try_prove_unreachable_no_rewrite(
                state,
                base_pc,
                prev_insn_pc,
            )
        {
            let entry_no_rw = RefineEntry::new(
                ok_no_rw.goal_root,
                ok_no_rw.sym.exprs,
                ok_no_rw.proof_bytes,
                BCF_BUNDLE_KIND_UNREACHABLE,
            );
            let nr_dup = env
                .bcf_proofs
                .iter()
                .any(|e| e.cond_hash == entry_no_rw.cond_hash);
            census_log("no_rw", state.pc, -1, -1, entry_no_rw.cond_hash, nr_dup);
            if !nr_dup {
                env.bcf_proofs.push(entry_no_rw);
            }
        }
        let mut cur = base_cid_dbg;
        for lean_depth in 0..2 {
            let Some(parent_cid) = cur
                .and_then(|cid| env.state_by_cache_id(cid))
                .and_then(|(_, s)| s.parent_cache_id)
            else {
                break;
            };
            for (rung, rok) in try_prove_unreachable_via_replay(env, state, parent_cid) {
                let rentry = RefineEntry::new(
                    rok.goal_root,
                    rok.sym.exprs,
                    rok.proof_bytes,
                    BCF_BUNDLE_KIND_UNREACHABLE,
                );
                replay_goals_produced += 1;
                let ra_dup = env
                    .bcf_proofs
                    .iter()
                    .any(|e| e.cond_hash == rentry.cond_hash);
                census_log(
                    "replay_anc",
                    state.pc,
                    lean_depth,
                    rung,
                    rentry.cond_hash,
                    ra_dup,
                );
                if !ra_dup {
                    env.bcf_proofs.push(rentry);
                }
            }
            // Aliased-VAR reconstruction at this ancestor (lean v4, the
            // anc_norw d<=1 slice — see the no_rw comment above).
            let anc_pc = env.state_by_cache_id(parent_cid).map(|(pc, _)| pc);
            if let Some(anc_pc) = anc_pc {
                let anc_prev = env.cached_prev_insn_pc(parent_cid);
                if let Some(ok_an) =
                    crate::refinement::refine_unreachable::try_prove_unreachable_no_rewrite(
                        state,
                        Some(anc_pc),
                        anc_prev,
                    )
                {
                    let entry_an = RefineEntry::new(
                        ok_an.goal_root,
                        ok_an.sym.exprs,
                        ok_an.proof_bytes,
                        BCF_BUNDLE_KIND_UNREACHABLE,
                    );
                    let an_dup = env
                        .bcf_proofs
                        .iter()
                        .any(|e| e.cond_hash == entry_an.cond_hash);
                    census_log(
                        "anc_norw",
                        state.pc,
                        lean_depth,
                        -1,
                        entry_an.cond_hash,
                        an_dup,
                    );
                    if !an_dup {
                        env.bcf_proofs.push(entry_an);
                    }
                }
            }
            cur = Some(parent_cid);
        }
        // FALLBACK: when the replay family produced NOTHING for this
        // reject — no cached base (base_cid=None, the base-less full-path
        // goal shape) or every replay diverged — the reconstruction
        // classes are the ONLY emitters for it, so fall through to the
        // full fat path for THIS reject instead of returning early.
        if replay_goals_produced > 0 {
            if let Ok(flush_path) = std::env::var("ALIVIO_BCF_EAGER_FLUSH") {
                let tmp = format!("{}.tmp", flush_path);
                if crate::refinement::bundle::write_bundle(
                    std::path::Path::new(&tmp),
                    &env.bcf_proofs,
                )
                .is_ok()
                {
                    let _ = std::fs::rename(&tmp, &flush_path);
                }
            }
            crate::analysis::flow::pruning::cache::mark_path_children_unsafe(
                env,
                state,
                base_cid_dbg,
            );
            return true;
        }
    }
    if let Ok(prefix) = std::env::var("ALIVIO_BCF_DUMP_PROOF") {
        let idx = env.bcf_proofs.len();
        let path = format!("{}.{}.bcf", prefix, idx);
        match std::fs::write(&path, &entry.proof_bytes) {
            Ok(_) => info!(target: "app", "[bcf] dumped raw proof to {}", path),
            Err(e) => log::warn!(target: "app", "[bcf] proof dump to {} failed: {}", path, e),
        }
    }
    env.bcf_proofs.push(entry);
    // ALIVIO_BCF_EAGER_FLUSH (default-OFF): eagerly flush the accumulated
    // bcf_proofs to a path after every discharge push, so the on-disk
    // bundle reflects current proofs even when the run is killed by a
    // wall-clock timeout before analyze() reaches its write_bundle.
    // Writes atomically (tmp+rename).
    if let Ok(flush_path) = std::env::var("ALIVIO_BCF_EAGER_FLUSH") {
        let tmp = format!("{}.tmp", flush_path);
        if crate::refinement::bundle::write_bundle(std::path::Path::new(&tmp), &env.bcf_proofs)
            .is_ok()
        {
            let _ = std::fs::rename(&tmp, &flush_path);
        }
    }
    // Also push the un-rewritten (aliased-VAR) form: the kernel queries
    // some discharge hashes via the aliased shape, so both forms stay in
    // the bundle alongside the kernel-shape rewrites.
    if let Some(ok_no_rw) = crate::refinement::refine_unreachable::try_prove_unreachable_no_rewrite(
        state,
        base_pc,
        prev_insn_pc,
    ) {
        let entry_no_rw = RefineEntry::new(
            ok_no_rw.goal_root,
            ok_no_rw.sym.exprs,
            ok_no_rw.proof_bytes,
            BCF_BUNDLE_KIND_UNREACHABLE,
        );
        let already_have = env
            .bcf_proofs
            .iter()
            .any(|e| e.cond_hash == entry_no_rw.cond_hash);
        census_log(
            "no_rw",
            state.pc,
            -1,
            -1,
            entry_no_rw.cond_hash,
            already_have,
        );
        if !already_have {
            info!(
                target: "app",
                "[bcf] path-unreachable (no-rewrite): cvc5 proof {} bytes (hash {:016x})",
                entry_no_rw.proof_bytes.len(),
                entry_no_rw.cond_hash
            );
            env.bcf_proofs.push(entry_no_rw);
        }
    }

    // Both-folds: ALSO emit the legacy-fold form of the same obligation —
    // the kernel folds per-site based on ITS state, so either form may
    // hash-match. ADDITIVE + deduped.
    {
        if let Some(ok_lf) =
            crate::refinement::refine_unreachable::try_prove_unreachable_fold_legacy(
                state,
                base_pc,
                prev_insn_pc,
            )
        {
            let entry_lf = RefineEntry::new(
                ok_lf.goal_root,
                ok_lf.sym.exprs,
                ok_lf.proof_bytes,
                BCF_BUNDLE_KIND_UNREACHABLE,
            );
            let lf_dup = env
                .bcf_proofs
                .iter()
                .any(|e| e.cond_hash == entry_lf.cond_hash);
            census_log("legacy_fold", state.pc, -1, -1, entry_lf.cond_hash, lf_dup);
            if !lf_dup {
                info!(
                    target: "app",
                    "[bcf] path-unreachable (legacy-fold): cvc5 proof {} bytes (hash {:016x})",
                    entry_lf.proof_bytes.len(), entry_lf.cond_hash
                );
                env.bcf_proofs.push(entry_lf);
            }
        }
    }

    // Trajectory-suffix twins of the NATURAL discharge (additive,
    // gated by BOTH_FOLDS like the legacy twin): the natural base may not be
    // a path-cond pc, so the anchor-union below never re-anchors exactly
    // there — emit the traj-window forms at (base_pc, prev_insn_pc) too.
    if base_pc.is_some() {
        for (t_label, okv) in [
            (
                "traj",
                crate::refinement::refine_unreachable::try_prove_unreachable_traj(
                    state,
                    base_pc,
                    prev_insn_pc,
                ),
            ),
            (
                "traj_lf",
                crate::refinement::refine_unreachable::try_prove_unreachable_traj_fold_legacy(
                    state,
                    base_pc,
                    prev_insn_pc,
                ),
            ),
            (
                "traj_no_rw",
                crate::refinement::refine_unreachable::try_prove_unreachable_traj_no_rewrite(
                    state,
                    base_pc,
                    prev_insn_pc,
                ),
            ),
        ] {
            if let Some(ok_t) = okv {
                let entry_t = RefineEntry::new(
                    ok_t.goal_root,
                    ok_t.sym.exprs,
                    ok_t.proof_bytes,
                    BCF_BUNDLE_KIND_UNREACHABLE,
                );
                let t_dup = env
                    .bcf_proofs
                    .iter()
                    .any(|e| e.cond_hash == entry_t.cond_hash);
                census_log(t_label, state.pc, -1, -1, entry_t.cond_hash, t_dup);
                if !t_dup {
                    info!(
                        target: "app",
                        "[bcf] path-unreachable (traj-natural): cvc5 proof {} bytes (hash {:016x})",
                        entry_t.proof_bytes.len(), entry_t.cond_hash
                    );
                    env.bcf_proofs.push(entry_t);
                }
            }
        }
    }

    // Register-filtered discharge (provenance-seeded, mirrors the kernel's
    // bcf_reg_expr data-dependency closure).
    //
    // After the immediate + ancestor PC-suffix discharges above, also emit
    // provenance-seeded register-filtered discharges: seed = the suffix's
    // most-recent branch reg, grown 1-2 def-use hops through the
    // value-expression DAG via the var_origin map, then keep only that
    // register set's branches + the bound preds materializing their VARs.
    // This synthesizes the kernel's small multi-register reject
    // conjunctions (bcf_reg_expr data-dependency closure) that the
    // PC-suffix filter alone can't isolate. Emitted at hop depths {1,2} ×
    // {rewrite, no-rewrite}; ADDITIVE + deduped by cond_hash, so it never
    // perturbs already-matched hashes — only adds.
    //
    // Soundness: only cvc5-PROVEN sub-conjunctions are emitted; the kernel
    // re-checks every proof on load, so a full-load = all proofs valid
    // (FA=0 floor preserved). Risk is bundle bloat, bounded by dedup +
    // the small per-anchor goal set.
    {
        use crate::refinement::refine_unreachable as ru;
        for &hops in &[1usize, 2usize] {
            for &use_rewrite in &[true, false] {
                let ok_opt = if use_rewrite {
                    ru::try_prove_unreachable_reg_filtered(state, hops)
                } else {
                    ru::try_prove_unreachable_reg_filtered_no_rewrite(state, hops)
                };
                if let Some(ok) = ok_opt {
                    let rf_entry = RefineEntry::new(
                        ok.goal_root,
                        ok.sym.exprs,
                        ok.proof_bytes,
                        BCF_BUNDLE_KIND_UNREACHABLE,
                    );
                    let rf_dup = env
                        .bcf_proofs
                        .iter()
                        .any(|e| e.cond_hash == rf_entry.cond_hash);
                    census_log(
                        if use_rewrite {
                            "regfilter_rw"
                        } else {
                            "regfilter_norw"
                        },
                        state.pc,
                        hops as i32,
                        -1,
                        rf_entry.cond_hash,
                        rf_dup,
                    );
                    if !rf_dup {
                        info!(target: "app",
                            "[bcf] reg-filtered (expt): {} bytes (hash {:016x}, hops={}, rw={})",
                            rf_entry.proof_bytes.len(), rf_entry.cond_hash, hops, use_rewrite);
                        env.bcf_proofs.push(rf_entry);
                    }
                }
            }
        }
    }

    // Synthetic ancestor-discharge emission. After the immediate-cache
    // discharge succeeds, walk the parent_cache_id chain backward and
    // emit additional discharges anchored at each ancestor cache. The
    // kernel sometimes queries a hash whose suffix base is DEEPER than
    // alivio's walker reaches in one segment of jmp_history — alivio's
    // jmp_history is segmented per-cache-event, so a single walker
    // call can only collect predicates within one segment; the kernel's
    // walker traverses one long history. Anchoring at each chain ancestor
    // produces the kernel-needed deeper hashes.
    //
    // ADDITIVE only: keeps the immediate-cache discharge (so existing
    // matched hashes preserve their byte-for-byte alignment) and dedups
    // by cond_hash before pushing.
    {
        // Ancestor-walk depth cap.
        let max_ancestor_depth: usize = 64;
        let mut cur_cid_opt = base_cid_dbg;
        let mut depth = 0;
        while depth < max_ancestor_depth {
            let Some(cur_cid) = cur_cid_opt else { break };
            // Live-then-retired: an evicted mid-chain ancestor must not
            // truncate the chain-discharge walk.
            let Some(parent_cid) = env
                .state_by_cache_id(cur_cid)
                .and_then(|(_, s)| s.parent_cache_id)
            else {
                break;
            };
            let Some((ancestor_pc, _)) = env.state_by_cache_id(parent_cid) else {
                break;
            };
            let ancestor_prev_pc = env.cached_prev_insn_pc(parent_cid);
            // Per-ancestor PC-suffix discharges (rewrite + no-rewrite).
            // Register-filtered discharges are PC-independent and emitted
            // once at top level, NOT per ancestor. All ADDITIVE + deduped.
            for &use_rewrite in &[true, false] {
                let ok_opt = if use_rewrite {
                    try_prove_unreachable(state, Some(ancestor_pc), ancestor_prev_pc)
                } else {
                    crate::refinement::refine_unreachable::try_prove_unreachable_no_rewrite(
                        state,
                        Some(ancestor_pc),
                        ancestor_prev_pc,
                    )
                };
                if let Some(ok) = ok_opt {
                    let extra_entry = RefineEntry::new(
                        ok.goal_root,
                        ok.sym.exprs,
                        ok.proof_bytes,
                        BCF_BUNDLE_KIND_UNREACHABLE,
                    );
                    let already_have = env
                        .bcf_proofs
                        .iter()
                        .any(|e| e.cond_hash == extra_entry.cond_hash);
                    census_log(
                        if use_rewrite { "anc_rw" } else { "anc_norw" },
                        state.pc,
                        depth as i32,
                        -1,
                        extra_entry.cond_hash,
                        already_have,
                    );
                    if std::env::var("ALIVIO_DUMP_DISCHARGE").ok().as_deref() == Some("1") {
                        eprintln!(
                            "[disc-ancestor] depth={} anchor_pc={} anchor_cid={} prev_pc={:?} rw={} hash={:016x} dup={}",
                            depth,
                            ancestor_pc,
                            parent_cid,
                            ancestor_prev_pc,
                            use_rewrite,
                            extra_entry.cond_hash,
                            already_have,
                        );
                    }
                    if !already_have {
                        info!(
                            target: "app",
                            "[bcf] ancestor-discharge: cvc5 proof {} bytes (hash {:016x}, depth={}, rw={})",
                            extra_entry.proof_bytes.len(),
                            extra_entry.cond_hash,
                            depth,
                            use_rewrite,
                        );
                        env.bcf_proofs.push(extra_entry);
                    }
                }
            }
            // Faithful base→reject replay re-anchored at THIS ancestor.
            // Re-executes from the ancestor's cached state, so the goal is
            // the kernel's exact bcf_track path cond for a replay starting
            // here. Additive + deduped by cond_hash.
            {
                for (rung, rok) in try_prove_unreachable_via_replay(env, state, parent_cid) {
                    let rentry = RefineEntry::new(
                        rok.goal_root,
                        rok.sym.exprs,
                        rok.proof_bytes,
                        BCF_BUNDLE_KIND_UNREACHABLE,
                    );
                    let ra_dup = env
                        .bcf_proofs
                        .iter()
                        .any(|e| e.cond_hash == rentry.cond_hash);
                    census_log(
                        "replay_anc",
                        state.pc,
                        depth as i32,
                        rung,
                        rentry.cond_hash,
                        ra_dup,
                    );
                    if std::env::var("ALIVIO_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1") {
                        eprintln!(
                            "[replay] ANCESTOR depth={} anchor_cid={} hash={:016x}",
                            depth, parent_cid, rentry.cond_hash
                        );
                    }
                    if !ra_dup {
                        env.bcf_proofs.push(rentry);
                    }
                }
            }
            cur_cid_opt = Some(parent_cid);
            depth += 1;
        }
    }

    // Mirror kernel bcf_refine (verifier.c:24580-81): cached
    // ancestors on the backtrack suffix of this path-unreachable
    // refinement are no longer prune-safe — a later arrival they'd
    // subsume may reach the same reject via a different path needing
    // its own path-unreachable bundle entry. Scoped to the same suffix
    // base as the path_conds (kernel parents[0..vstate_cnt-1]).
    crate::analysis::flow::pruning::cache::mark_path_children_unsafe(env, state, base_cid_dbg);
    true
}
