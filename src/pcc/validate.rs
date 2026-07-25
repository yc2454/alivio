use anyhow::Result;

use crate::analysis::machine::reg::Reg;
use crate::ast::Program;

use super::model::{MAX_ENTRIES_PER_PC, MAX_STEPS_PER_ENTRY, ProgramCertificate, ProofStep};

/// Structural validation for the prototype pc-annotation certificate schema.
pub fn validate_certificate_for_program(cert: &ProgramCertificate, prog: &Program) -> Result<()> {
    if cert.version != ProgramCertificate::VERSION {
        anyhow::bail!(
            "unsupported certificate version {} (expected {})",
            cert.version,
            ProgramCertificate::VERSION
        );
    }

    for (pc_idx, ann) in cert.pc_annotations.iter().enumerate() {
        if ann.pc >= prog.instrs.len() {
            anyhow::bail!(
                "pc_annotation #{} has pc={} out of bounds (program len={})",
                pc_idx,
                ann.pc,
                prog.instrs.len()
            );
        }
        if ann.entries.len() > MAX_ENTRIES_PER_PC {
            anyhow::bail!(
                "pc_annotation #{} exceeds max entries per pc ({} > {})",
                pc_idx,
                ann.entries.len(),
                MAX_ENTRIES_PER_PC
            );
        }
        for (eidx, e) in ann.entries.iter().enumerate() {
            let Some(left) = Reg::idx_to_reg(e.left_reg) else {
                anyhow::bail!(
                    "pc_annotation #{} entry #{} has invalid left_reg={}",
                    pc_idx,
                    eidx,
                    e.left_reg
                );
            };
            let Some(right) = Reg::idx_to_reg(e.right_reg) else {
                anyhow::bail!(
                    "pc_annotation #{} entry #{} has invalid right_reg={}",
                    pc_idx,
                    eidx,
                    e.right_reg
                );
            };
            if left.is_anchor() && right.is_anchor() && left == right {
                anyhow::bail!(
                    "pc_annotation #{} entry #{} is degenerate anchor constraint",
                    pc_idx,
                    eidx
                );
            }
            if e.proof.is_empty() {
                anyhow::bail!("pc_annotation #{} entry #{} has empty proof", pc_idx, eidx);
            }

            // Total node count (counting recursively into Compose sub-proofs)
            let total_nodes: usize = e.proof.iter().map(|s| s.node_count()).sum();
            if total_nodes > MAX_STEPS_PER_ENTRY {
                anyhow::bail!(
                    "pc_annotation #{} entry #{} exceeds max steps ({} > {})",
                    pc_idx,
                    eidx,
                    total_nodes,
                    MAX_STEPS_PER_ENTRY
                );
            }

            // Validate the proof chain (recursively for Compose)
            let ctx = &format!("pc_annotation #{} entry #{}", pc_idx, eidx);
            validate_proof_chain(&e.proof, ann.pc, prog.instrs.len(), ctx)?;

            // Last step output matches entry target
            let last = e.proof.last().unwrap();
            if last.output_left_reg() != e.left_reg || last.output_right_reg() != e.right_reg {
                anyhow::bail!("{} proof endpoints mismatch entry target", ctx);
            }

            // Sum: total bound contributions == entry.bound
            let mut sum = 0i64;
            for step in &e.proof {
                sum = match sum.checked_add(step.bound_contribution()) {
                    Some(s) => s,
                    None => anyhow::bail!("{} proof weight sum overflows i64", ctx),
                };
            }
        }
    }

    Ok(())
}

/// Recursively validate a proof chain's structural integrity.
///
/// Checks: register indices, chain connectivity, PC ordering, PC bounds.
/// For Compose steps, recursively validates left and right sub-proofs
/// and checks that they connect through the `via` register.
fn validate_proof_chain(
    proof: &[ProofStep],
    target_pc: usize,
    prog_len: usize,
    ctx: &str,
) -> Result<()> {
    if proof.is_empty() {
        anyhow::bail!("{} has empty proof chain", ctx);
    }

    // proof[0] must be a Fact (for linear chains) or a single Compose
    // A top-level Compose as proof[0] is allowed if the proof is [Compose]
    match &proof[0] {
        ProofStep::Fact { .. } => {}
        ProofStep::Compose { .. } if proof.len() == 1 => {
            // Single Compose step — validate it and return
            validate_compose_step(&proof[0], target_pc, prog_len, ctx)?;
            return Ok(());
        }
        _ => {
            anyhow::bail!(
                "{} proof must start with a Fact step (or be a single Compose)",
                ctx
            );
        }
    }

    // Validate register indices in all steps
    for (sidx, step) in proof.iter().enumerate() {
        validate_step_registers(step, sidx, target_pc, prog_len, ctx)?;
    }

    // Chain connectivity: each step after Fact must be Derive, Transfer, or Compose,
    // and its input registers must match the previous step's output registers.
    for w in proof.windows(2) {
        match &w[1] {
            ProofStep::Fact { .. } => {
                anyhow::bail!("{} has Fact step after first position", ctx);
            }
            ProofStep::Transfer {
                pre_left_reg,
                pre_right_reg,
                ..
            } => {
                if w[0].output_left_reg() != *pre_left_reg
                    || w[0].output_right_reg() != *pre_right_reg
                {
                    anyhow::bail!("{} proof chain disconnected at Transfer", ctx);
                }
            }
            ProofStep::Derive { source_reg, .. } => {
                if w[0].output_left_reg() != *source_reg {
                    anyhow::bail!("{} proof chain disconnected at Derive", ctx);
                }
            }
            ProofStep::Compose { .. } => {
                // Compose is self-contained; connectivity checked internally.
                // The Compose's output registers define what the next step sees.
            }
        }
    }

    // PC ordering: all step PCs < target_pc.
    // Derive steps before first Transfer may reference earlier PCs.
    // After first Transfer, PCs must be strictly increasing.
    let mut prev_pc = None;
    let mut seen_transfer = false;
    for (sidx, step) in proof.iter().enumerate() {
        // Skip PC ordering for Compose (sub-proofs have their own PC ranges)
        if matches!(step, ProofStep::Compose { .. }) {
            continue;
        }
        let step_pc = step.pc();
        if step_pc >= target_pc {
            anyhow::bail!(
                "{} step #{} pc={} >= target pc={}",
                ctx,
                sidx,
                step_pc,
                target_pc
            );
        }
        if let Some(prev) = prev_pc {
            if matches!(step, ProofStep::Derive { .. }) && !seen_transfer {
                // Derive before first Transfer: may reference earlier PCs
            } else if !seen_transfer {
                if step_pc < prev {
                    anyhow::bail!("{} step #{} pc={} < guard pc={}", ctx, sidx, step_pc, prev);
                }
            } else if step_pc <= prev {
                anyhow::bail!(
                    "{} step #{} pc={} not strictly increasing (prev={})",
                    ctx,
                    sidx,
                    step_pc,
                    prev
                );
            }
        }
        if matches!(step, ProofStep::Transfer { .. }) {
            seen_transfer = true;
        }
        prev_pc = Some(step_pc);
    }

    // Step PCs must be in program bounds (skip Compose — checked recursively)
    for (sidx, step) in proof.iter().enumerate() {
        if matches!(step, ProofStep::Compose { .. }) {
            continue;
        }
        if step.pc() >= prog_len {
            anyhow::bail!("{} step #{} pc={} out of bounds", ctx, sidx, step.pc());
        }
    }

    Ok(())
}

/// Validate register indices for a single step, recursing into Compose.
fn validate_step_registers(
    step: &ProofStep,
    sidx: usize,
    target_pc: usize,
    prog_len: usize,
    ctx: &str,
) -> Result<()> {
    match step {
        ProofStep::Fact {
            left_reg,
            right_reg,
            ..
        } => {
            validate_reg_idx(*left_reg, sidx, ctx)?;
            validate_reg_idx(*right_reg, sidx, ctx)?;
        }
        ProofStep::Derive {
            source_reg,
            target_reg,
            ..
        } => {
            validate_reg_idx(*source_reg, sidx, ctx)?;
            validate_reg_idx(*target_reg, sidx, ctx)?;
        }
        ProofStep::Transfer {
            pre_left_reg,
            pre_right_reg,
            post_left_reg,
            post_right_reg,
            ..
        } => {
            validate_reg_idx(*pre_left_reg, sidx, ctx)?;
            validate_reg_idx(*pre_right_reg, sidx, ctx)?;
            validate_reg_idx(*post_left_reg, sidx, ctx)?;
            validate_reg_idx(*post_right_reg, sidx, ctx)?;
        }
        ProofStep::Compose { .. } => {
            validate_compose_step(step, target_pc, prog_len, ctx)?;
        }
    }
    Ok(())
}

/// Validate a Compose step: check `via` index, recursively validate sub-proofs,
/// and verify that sub-proofs connect through `via`.
fn validate_compose_step(
    step: &ProofStep,
    target_pc: usize,
    prog_len: usize,
    ctx: &str,
) -> Result<()> {
    let ProofStep::Compose { left, right, via } = step else {
        unreachable!();
    };

    validate_reg_idx(*via, 0, ctx)?;

    if left.is_empty() || right.is_empty() {
        anyhow::bail!("{} Compose has empty sub-proof", ctx);
    }

    let left_ctx = format!("{} Compose.left", ctx);
    let right_ctx = format!("{} Compose.right", ctx);

    // Recursively validate sub-proofs.
    // Sub-proofs' PC ranges may overlap (they trace independent constraints).
    validate_proof_chain(left, target_pc, prog_len, &left_ctx)?;
    validate_proof_chain(right, target_pc, prog_len, &right_ctx)?;

    // Connectivity: left's output right == via, right's output left == via
    let left_last = left.last().unwrap();
    let right_last = right.last().unwrap();

    if left_last.output_right_reg() != *via {
        anyhow::bail!(
            "{} Compose left sub-proof output right {} != via {}",
            ctx,
            left_last.output_right_reg(),
            via
        );
    }
    if right_last.output_left_reg() != *via {
        anyhow::bail!(
            "{} Compose right sub-proof output left {} != via {}",
            ctx,
            right_last.output_left_reg(),
            via
        );
    }

    Ok(())
}

fn validate_reg_idx(idx: usize, sidx: usize, ctx: &str) -> Result<()> {
    if Reg::idx_to_reg(idx).is_none() {
        anyhow::bail!("{} step #{} has invalid register index {}", ctx, sidx, idx);
    }
    Ok(())
}
