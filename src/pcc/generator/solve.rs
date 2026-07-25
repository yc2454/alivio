use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::ast::Program;
use crate::domains::dbm::Dbm;
use log::debug;

use super::super::model::ProofStep;
use super::derive::try_derive_chain;
use super::trace::{backward_trace, transfer_deltas_sound};

// ---------------------------------------------------------------------------
// Provenance-based Compose generation (for transitive closure)
// ---------------------------------------------------------------------------

/// Attempt to generate a proof using provenance-based transitive composition.
///
/// When the zone constraint `target_i - target_j <= target_bound` is derived by
/// Floyd-Warshall closure through intermediate registers, `reconstruct_path`
/// decomposes it into primitive edges. For each edge, we try `backward_trace`
/// or `try_derive_chain` to generate a sub-proof. If all segments succeed,
/// we fold them into nested `Compose` nodes.
// Recursive constraint solver: tries linear replay, alias substitution, and
// provenance-guided composition in one search tree.
pub(super) fn solve_constraint(
    prog: &Program,
    zone_dbms: &[Dbm],
    interval_states: &[State],
    target_pc: usize,
    left: Reg,
    right: Reg,
    bound: i64,
    depth: usize,
    base_reg_for_alias: Option<Reg>,
    anchor_for_alias: Option<Reg>,
) -> Option<Vec<ProofStep>> {
    const MAX_DEPTH: usize = 4;
    if depth > MAX_DEPTH {
        return None;
    }

    // 1) Linear backward replay (Fact + Transfer chain)
    if let Some((_, _, _, _, proof)) = backward_trace(
        prog,
        zone_dbms,
        interval_states,
        target_pc,
        left,
        right,
        bound,
    )
    .filter(|(_, _, _, _, proof)| transfer_deltas_sound(proof, prog, interval_states))
    {
        return Some(proof);
    }

    // 2) Alias substitution (Derive) when pattern fits the load shape
    if let (Some(base), Some(anchor)) = (base_reg_for_alias, anchor_for_alias)
        && let Some(proof) = try_derive_chain(
            prog,
            zone_dbms,
            interval_states,
            target_pc,
            base,
            anchor,
            bound,
        )
    {
        return Some(proof);
    }

    // 3) Provenance-guided composition (transitive closure)
    let dbm = zone_dbms.get(target_pc)?;
    let edges = dbm.reconstruct_path(left, right)?;
    if edges.len() < 2 {
        return None; // single-edge path already handled by replay
    }

    // Build sub-proofs for each primitive edge.
    let mut sub_proofs: Vec<Vec<ProofStep>> = Vec::new();
    for edge in &edges {
        debug!(
            target: "pcc-gen",
            "[PCC-GEN] target={}: compose edge {}-{} <= {} (pc={})",
            target_pc,
            edge.to.name(),
            edge.from.name(),
            edge.weight,
            edge.pc,
        );
        let sub = solve_constraint(
            prog,
            zone_dbms,
            interval_states,
            target_pc,
            edge.to,
            edge.from,
            edge.weight,
            depth + 1,
            None,
            None,
        )?;
        sub_proofs.push(sub);
    }

    // Fold sub-proofs right-associatively into nested Compose nodes.
    // For edges [A-K1, K1-K2, K2-B]:
    //   Compose(A-K1, Compose(K1-K2, K2-B, via=K2), via=K1)
    let mut it = sub_proofs.into_iter().rev();
    let mut result = it.next().unwrap(); // rightmost
    for left_proof in it {
        let via = left_proof.last().map(|s| s.output_right_reg()).unwrap_or(0);
        result = vec![ProofStep::Compose {
            left: left_proof,
            right: result,
            via,
        }];
    }

    Some(result)
}
