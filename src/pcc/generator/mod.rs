use std::collections::BTreeMap;

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use crate::ast::{AluOp, Instr, Operand, Program};
use crate::domains::dbm::{Dbm, INF};
use crate::parsing::elf::BpfMapDef;
use log::debug;

use super::model::{AnnotationEntry, PcAnnotation, ProgramCertificate, ProofStep};
use super::program_hash;

mod bounds;
mod derive;
mod solve;
mod trace;

use bounds::{
    access_anchor_and_bound, find_same_map_anchor, interval_already_proves_access, load_info,
    zone_upper_bound,
};
use solve::solve_constraint;

// ---------------------------------------------------------------------------
// Certificate generation entry point
// ---------------------------------------------------------------------------

/// Generate a certificate using backward tracing from zone analysis.
///
/// For each candidate load instruction, traces backward to the divergence
/// point where zone and interval first disagree, emitting a proof chain
/// of [Fact, Derive*, Transfer+].
pub fn generate_certificate(
    prog: &Program,
    zone_dbms: &[Dbm],
    interval_states: &[State],
    map_defs: &[BpfMapDef],
) -> ProgramCertificate {
    let mut cert = ProgramCertificate::empty(program_hash(prog));
    if prog.instrs.is_empty() {
        return cert;
    }

    let mut by_pc: BTreeMap<usize, Vec<AnnotationEntry>> = BTreeMap::new();

    for target_pc in 0..prog.instrs.len() {
        let instr = &prog.instrs[target_pc];
        let Some((base, off, size)) = load_info(instr) else {
            continue;
        };

        let off_i64 = off as i64;
        let size_i64 = size.bytes() as i64;

        // Determine anchor and required bound from the base register's pointer type.
        // Use the interval state's type info (available at the load PC).
        let state = if target_pc < interval_states.len() {
            &interval_states[target_pc]
        } else {
            continue;
        };
        let Some((anchor_end, required)) =
            access_anchor_and_bound(state, base, off_i64, size_i64, map_defs)
        else {
            continue;
        };

        // Query zone: does the zone prove the access is safe?
        // Use the DBM at the target PC (the pre-state just before the load executes).
        let Some(dbm) = zone_dbms.get(target_pc) else {
            continue;
        };

        // Try direct anchor first (works for packet/stack where zone tracks base-anchor).
        // For maps, zone doesn't track base-Zero as a buffer offset, so the direct path
        // typically returns Some but too large (255 from AND mask, not buffer-relative).
        // Fall through to the transitive path: find a same-map register k where zone
        // tracks base-k and k has a known type-level offset from the map buffer start.
        let direct_ok = zone_upper_bound(dbm, base, anchor_end).filter(|&ub| ub <= required);
        let (effective_anchor, zone_ub) = if let Some(ub) = direct_ok {
            (anchor_end, ub)
        } else if let RegType::PtrToMapValue { map_idx, .. } = state.types.get(base) {
            // Transitive: scan for a same-map register k with finite zone_ub(base, k)
            // such that zone_ub(base, k) + k.type_offset <= required.
            match find_same_map_anchor(state, dbm, base, map_idx, required) {
                Some(pair) => pair,
                None => continue,
            }
        } else if zone_upper_bound(dbm, base, anchor_end).is_some() {
            continue; // zone has a bound but it's not tight enough
        } else {
            continue; // zone doesn't track this pair
        };

        // Query interval: does the interval verifier already prove it?
        if interval_already_proves_access(state, base, off_i64, size_i64, map_defs) {
            continue; // interval already sufficient, no PCC needed
        }

        debug!(
            target: "pcc-gen",
            "[PCC-GEN] target={}: candidate load {} anchor={} effective={} (zone_ub={}, required={})",
            target_pc, base.name(), anchor_end.name(), effective_anchor.name(), zone_ub, required,
        );

        // Backward trace to find the divergence point.
        // Use effective_anchor (may differ from anchor_end for maps).
        let proof = if let Some(proof) = solve_constraint(
            prog,
            zone_dbms,
            interval_states,
            target_pc,
            base,
            effective_anchor,
            zone_ub,
            0,
            Some(base),
            Some(effective_anchor),
        ) {
            proof
        } else {
            debug!(
                target: "pcc-gen",
                "[PCC-GEN] target={}: all generation strategies failed, skipping",
                target_pc,
            );
            continue;
        };

        // Compute the entry bound from the proof chain.
        let bound: i64 = proof.iter().map(|s| s.bound_contribution()).sum();

        by_pc.entry(target_pc).or_default().push(AnnotationEntry {
            left_reg: base.idx(),
            right_reg: effective_anchor.idx(),
            bound,
            proof,
        });
    }

    cert.pc_annotations = by_pc
        .into_iter()
        .map(|(pc, entries)| PcAnnotation { pc, entries })
        .collect();
    cert
}

/// Legacy generator (Fact-only, no Transfer steps) — kept for backward compatibility.
#[allow(dead_code)]
pub fn generate_prototype_certificate_from_zone(
    prog: &Program,
    zone_dbms: &[Dbm],
) -> ProgramCertificate {
    let mut cert = ProgramCertificate::empty(program_hash(prog));
    if prog.instrs.len() < 2 {
        return cert;
    }

    let mut by_pc: BTreeMap<usize, Vec<AnnotationEntry>> = BTreeMap::new();

    for pred_pc in 0..(prog.instrs.len() - 1) {
        let Some(Instr::Alu {
            op: AluOp::Add,
            dst,
            src: Operand::Reg(src),
            ..
        }) = prog.instrs.get(pred_pc)
        else {
            continue;
        };
        let succ_pc = pred_pc + 1;
        let Some(Instr::Load {
            size, base, off, ..
        }) = prog.instrs.get(succ_pc)
        else {
            continue;
        };
        if base != dst {
            continue;
        }
        let Some(dbm) = zone_dbms.get(pred_pc) else {
            continue;
        };

        let d_dst_data = dbm.get(*dst, Reg::AnchorData);
        let d_data_end = dbm.get(Reg::AnchorData, Reg::AnchorDataEnd);
        let src_umax = dbm.get(*src, Reg::Zero);
        if d_dst_data >= INF || d_data_end >= INF || src_umax >= INF {
            continue;
        }

        let Some(step1_c) = d_dst_data.checked_add(src_umax) else {
            continue;
        };
        let step2_c = d_data_end;
        let Some(target_c) = step1_c.checked_add(step2_c) else {
            continue;
        };

        let access_need = -((*off as i64) + size.bytes() as i64);
        if target_c > access_need {
            continue;
        }

        by_pc.entry(succ_pc).or_default().push(AnnotationEntry {
            left_reg: dst.idx(),
            right_reg: Reg::AnchorDataEnd.idx(),
            bound: target_c,
            proof: vec![ProofStep::Fact {
                pc: pred_pc,
                left_reg: dst.idx(),
                right_reg: Reg::AnchorDataEnd.idx(),
                c: target_c,
            }],
        });
    }

    cert.pc_annotations = by_pc
        .into_iter()
        .map(|(pc, entries)| PcAnnotation { pc, entries })
        .collect();
    cert
}
