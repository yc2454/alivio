// src/analysis/flow/diag.rs
//
// Diagnostic / observability helpers for the analysis pass. Two kinds:
//   * env-var config readers (ZOVIA_DUMP_* / ZOVIA_DIAG_PCS) queried by
//     record_state / merging / run_worklist to decide whether to emit an
//     instrumentation line.
//   * end-of-run audit dumps over `VerifierEnv` state (visit counts,
//     subsumption-miss histogram).
// All read-only; none affect analysis results.

use crate::analysis::machine::env::VerifierEnv;

/// Cache-growth instrumentation flag. When set, `record_state` prints
/// `(pc, cache_size, distinct_type_sigs)` to stderr on every insert.
/// Used to diagnose state-graph traversal divergence between
/// flag-off and flag-on under the precision rebuild.
pub fn dump_cache_growth_enabled() -> bool {
    std::env::var("ZOVIA_DUMP_CACHE_GROWTH").ok().as_deref() == Some("1")
}

/// If set to a numeric PC, `record_state` dumps full per-register
/// type signatures at that PC for every cached state on each insert.
/// Used to identify which register's type-shape diverges between
/// flag-off and flag-on.
pub fn dump_cache_growth_pc() -> Option<usize> {
    std::env::var("ZOVIA_DUMP_CACHE_GROWTH_PC")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Comma-separated list of PCs (e.g. `ZOVIA_DIAG_PCS=1972,1974,1976,1986,1987`).
/// run_worklist emits a compact per-arrival diagnostic at each: register
/// types + ranges + tnums before/after type-conflict resolution, the
/// prune decision, and successor PCs. Distinguishes the three
/// type-collapse loss mechanisms (merge-demote vs precision-strip vs
/// subsumption) in a single run.
pub fn diag_pcs() -> Option<std::collections::HashSet<usize>> {
    let raw = std::env::var("ZOVIA_DIAG_PCS").ok()?;
    let set: std::collections::HashSet<usize> = raw
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if set.is_empty() { None } else { Some(set) }
}

/// If set to a numeric PC, `record_state` dumps the env's
/// `precise_pcs` set (eviction-resistant precision marks written by
/// `mark_chain_precision_backward`) on every insert at that PC.
/// Diagnostic for designing pruning-side wideners that consume
/// `precise_pcs` — surfaces what the walker has actually marked by
/// the time the cache fires at the target loop head.
pub fn dump_precise_pcs_pc() -> Option<usize> {
    std::env::var("ZOVIA_DUMP_PRECISE_PCS_PC")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Tiny helper for the audit dump.
fn pct(n: u64, d: u64) -> f64 {
    if d == 0 {
        0.0
    } else {
        (n as f64 / d as f64) * 100.0
    }
}

/// Audit dump: per-PC non-pruned state-expansion count.
/// Triggered by `ZOVIA_DUMP_VISITS=1`. Used to localize path-explosion
/// hotspots by diffing against the kernel verifier's per-PC visit
/// count from the log_level-2 trace (`<pc>: (...) <insn>` lines).
pub fn dump_pc_visit_count(env: &VerifierEnv) {
    let mut pairs: Vec<(usize, u64)> =
        env.pc_visit_count.iter().map(|(&pc, &n)| (pc, n)).collect();
    pairs.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    eprintln!("\n=== ZOVIA per-PC visit count (non-pruned expansions) ===");
    eprintln!("  total expansions: {}    distinct pcs: {}", env.insn_processed, pairs.len());
    eprintln!("  top 100 pcs by visit count:");
    for (pc, n) in pairs.iter().take(100) {
        eprintln!("    pc={:<5} visits={}", pc, n);
    }
    // Full machine-diffable table (pc order) for kernel [ZK visit] diffs.
    let mut by_pc = pairs.clone();
    by_pc.sort_by_key(|&(pc, _)| pc);
    for (pc, n) in by_pc {
        eprintln!("[zvisit] {} {}", pc, n);
    }
}

/// Audit dump: per-PC subsumption-miss histogram + global totals.
/// Triggered by `ZOVIA_DUMP_PRUNING=1`. Output goes to stderr (so it
/// doesn't tangle with verifier stdout when piping). Format is
/// hand-rolled tabular text — the consumer is a human reading one
/// test's audit output, not a machine.
pub fn dump_subsumption_miss_histogram(env: &VerifierEnv) {
    use crate::analysis::machine::env::SubsumptionMissReason;

    // Global totals across all PCs.
    let mut global = [0u64; 9];
    for buckets in env.subsumption_misses.values() {
        for i in 0..9 {
            global[i] = global[i].saturating_add(buckets[i]);
        }
    }
    let total_misses: u64 = global.iter().sum();

    // Use the lifetime counters, NOT `state_metrics.hit_cnt`. The
    // per-state hit/miss counters disappear when the state is evicted
    // by `record_state`'s max_states_per_pc drain (cap = 8 by
    // default), so reading them at end-of-run undercounts wildly on
    // workloads with > 8 distinct cached states per PC.
    let total_hits: u64 = env.pruning_stats.lifetime_hits;
    let total_misses_lifetime: u64 = env.pruning_stats.lifetime_misses;
    let _ = env.state_metrics.values().flatten().count(); // keep import path used
    let total_cached: u64 = env
        .state_metrics
        .values()
        .map(|v| v.len() as u64)
        .sum();
    let n_pcs = env.subsumption_misses.len();

    let ps = &env.pruning_stats;
    eprintln!("\n=== ZOVIA pruning audit ===");
    eprintln!(
        "  insn_processed: {}    distinct PCs cached: {}    total cached states: {}",
        env.insn_processed,
        env.explored_states.len(),
        total_cached
    );
    eprintln!(
        "  should_prune calls: {}",
        ps.should_prune_calls
    );
    eprintln!(
        "    not a prune point:    {:>10}  ({:>5.1}%)",
        ps.not_prune_point,
        pct(ps.not_prune_point, ps.should_prune_calls)
    );
    eprintln!(
        "    on-path re-entry:     {:>10}  ({:>5.1}%)",
        ps.on_path_skip,
        pct(ps.on_path_skip, ps.should_prune_calls)
    );
    eprintln!(
        "    no prev states (1st): {:>10}  ({:>5.1}%)",
        ps.no_prev_states,
        pct(ps.no_prev_states, ps.should_prune_calls)
    );
    eprintln!(
        "    standard subsumption: {:>10}  ({:>5.1}%)",
        ps.std_pruning_calls,
        pct(ps.std_pruning_calls, ps.should_prune_calls)
    );
    eprintln!(
        "    loop subsumption:     {:>10}  ({:>5.1}%)",
        ps.loop_pruning_calls,
        pct(ps.loop_pruning_calls, ps.should_prune_calls)
    );
    eprintln!(
        "      of which bailed (no_cond_exit):    {} ({:.1}% of loop calls)",
        ps.loop_no_cond_exit,
        pct(ps.loop_no_cond_exit, ps.loop_pruning_calls)
    );
    eprintln!(
        "      of which actually walked prev_states: {}",
        ps.loop_walks_attempted
    );
    eprintln!(
        "        no_prev / hit / miss / convergence-pruned: {} / {} / {} / {}",
        ps.loop_walks_no_prev,
        ps.loop_walks_hit,
        ps.loop_walks_miss,
        ps.loop_walks_pruned_via_convergence,
    );
    eprintln!(
        "    may_goto RANGE_WITHIN hits: {}",
        ps.may_goto_range_within_hits
    );
    eprintln!(
        "    children_unsafe skips:    {:>10}    ← BCF-discharge cache invalidations",
        ps.children_unsafe_skips
    );
    eprintln!(
        "  cache hits: {total_hits}    cache misses: {total_misses_lifetime} (per-reason histogram below sums to {total_misses})    miss-PCs: {n_pcs}"
    );
    eprintln!("  miss reasons (first-rejecting check, % of total misses):");
    let mut ranked: Vec<(SubsumptionMissReason, u64)> = SubsumptionMissReason::ALL
        .iter()
        .map(|&r| (r, global[r.idx()]))
        .collect();
    ranked.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    let denom = total_misses.max(1) as f64;
    for (r, c) in &ranked {
        eprintln!(
            "    {:>16}  {:>10}   ({:>5.1}%)",
            r.label(),
            c,
            (*c as f64 / denom) * 100.0
        );
    }

    // Top-5 PCs by miss count, with their per-PC reason breakdown.
    let mut by_pc: Vec<(usize, u64, [u64; 9])> = env
        .subsumption_misses
        .iter()
        .map(|(&pc, buckets)| (pc, buckets.iter().sum::<u64>(), *buckets))
        .collect();
    by_pc.sort_by_key(|(_, total, _)| std::cmp::Reverse(*total));
    eprintln!("  top PCs by miss count:");
    for (pc, total, buckets) in by_pc.iter().take(8) {
        let dom = SubsumptionMissReason::ALL
            .iter()
            .max_by_key(|r| buckets[r.idx()])
            .unwrap();
        let dom_share = buckets[dom.idx()] as f64 / (*total as f64).max(1.0) * 100.0;
        let cached_at_pc = env
            .state_metrics
            .get(pc)
            .map(|v| v.len())
            .unwrap_or(0);
        eprintln!(
            "    pc={pc:<5}  misses={total:<8}  cached={cached_at_pc:<3}  dominant={} ({:.0}%)",
            dom.label(),
            dom_share
        );
    }
    eprintln!();
}
