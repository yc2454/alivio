// src/analysis/flow/callback_analysis.rs
//
// Static, whole-program pre-passes over callback (PSEUDO_FUNC) subprogs.
// Each scans a cb subprog's straight-line body once at analysis init and
// returns a per-subprog fact consumed later by the transfer functions.
// Pure functions over `(prog, btf)` — no `VerifierEnv` state. Populated
// into `VerifierEnv` fields at `VerifierEnv::new`.

use std::collections::{HashMap, HashSet};

/// Static pre-pass identifying subprog entry PCs whose body is unsafe
/// to use as a graph-add (`bpf_rbtree_add_impl` / `bpf_list_push_*`)
/// `less` callback. Kernel verifier.c v6.15 rejects callbacks that
/// re-invoke graph-add/remove kfuncs, take/release spin_locks, or
/// `bpf_throw`. The kernel's checks include:
///
///   - "rbtree_remove not allowed in rbtree cb"
///   - "arg#1 expected pointer to allocated object" (when the cb
///     calls bpf_rbtree_add → recursion poisons the alloc-arg shape)
///   - "can't spin_{lock,unlock} in rbtree cb"
///   - "bpf_throw not allowed in rbtree cb"
///
/// We don't model these per-msg; we conservatively reject if any
/// forbidden op is reachable in the subprog's straight-line body
/// between its entry PC and its `Exit`. Subprogs are identified by
/// being targets of `LD_IMM64 BPF_PSEUDO_FUNC` (the way callbacks are
/// materialized).
pub fn compute_tainted_cb_subprogs(
    prog: &crate::ast::Program,
    btf: &crate::parsing::btf::BtfContext,
) -> HashSet<usize> {
    use crate::ast::{CallKind, Instr, MapLoadKind};
    use crate::common::constants;

    // Collect every PSEUDO_FUNC subprog entry PC. These are the only
    // PCs that can ever land in `RegType::PtrToCallback`.
    let mut entries: Vec<usize> = Vec::new();
    for insn in &prog.instrs {
        if let Instr::LoadMap {
            kind: MapLoadKind::PseudoFunc { subprog_pc },
            ..
        } = insn
        {
            entries.push(*subprog_pc as usize);
        }
    }
    entries.sort();
    entries.dedup();

    // Sorted full subprog-entry list (incl. main + every CallRel target +
    // every PSEUDO_FUNC target) used to bound each cb subprog's body
    // range — the Exit at end_pc is conservatively the next entry PC.
    let mut all_entries: Vec<usize> = vec![0];
    for insn in &prog.instrs {
        match insn {
            Instr::CallRel { target } => all_entries.push(*target),
            Instr::LoadMap {
                kind: MapLoadKind::PseudoFunc { subprog_pc },
                ..
            } => all_entries.push(*subprog_pc as usize),
            _ => {}
        }
    }
    all_entries.sort();
    all_entries.dedup();

    let is_forbidden_kfunc = |name: &str| {
        matches!(
            name,
            "bpf_throw"
                | "bpf_rbtree_add_impl"
                | "bpf_rbtree_remove"
                | "bpf_rbtree_first"
                | "bpf_list_push_front_impl"
                | "bpf_list_push_back_impl"
                | "bpf_list_pop_front"
                | "bpf_list_pop_back"
                | "bpf_obj_drop_impl"
                | "bpf_obj_new_impl"
                | "bpf_refcount_acquire_impl"
                | "bpf_rcu_read_lock"
                | "bpf_rcu_read_unlock"
        )
    };

    let mut tainted: HashSet<usize> = HashSet::new();
    for &start in &entries {
        let end = all_entries
            .iter()
            .find(|&&pc| pc > start)
            .copied()
            .unwrap_or(prog.instrs.len());
        let body = &prog.instrs[start..end.min(prog.instrs.len())];
        let mut bad = false;
        for insn in body {
            if let Instr::Call { kind } = insn {
                match *kind {
                    CallKind::Helper { id } => {
                        if id == constants::BPF_SPIN_LOCK || id == constants::BPF_SPIN_UNLOCK {
                            bad = true;
                            break;
                        }
                    }
                    CallKind::Kfunc { btf_id, .. } => {
                        if let Some(name) = btf.kfunc_name(btf_id)
                            && is_forbidden_kfunc(name)
                        {
                            bad = true;
                            break;
                        }
                    }
                }
            }
        }
        if bad {
            tainted.insert(start);
        }
    }
    tainted
}

/// Per-cb-subprog flag: does the body directly call any
/// dynptr-(re)initializing helper or kfunc? Used to suppress the
/// kernel-pessimism slice invalidation in `transfer_callback_helper`
/// when the cb provably cannot re-init the source dynptr.
pub fn compute_cb_body_can_reinit_dynptr(
    prog: &crate::ast::Program,
    btf: &crate::parsing::btf::BtfContext,
) -> HashSet<usize> {
    use crate::ast::{CallKind, Instr, MapLoadKind};
    use crate::common::constants;

    let mut entries: Vec<usize> = Vec::new();
    for insn in &prog.instrs {
        if let Instr::LoadMap {
            kind: MapLoadKind::PseudoFunc { subprog_pc },
            ..
        } = insn
        {
            entries.push(*subprog_pc as usize);
        }
    }
    entries.sort();
    entries.dedup();

    let mut all_entries: Vec<usize> = vec![0];
    for insn in &prog.instrs {
        match insn {
            Instr::CallRel { target } => all_entries.push(*target),
            Instr::LoadMap {
                kind: MapLoadKind::PseudoFunc { subprog_pc },
                ..
            } => all_entries.push(*subprog_pc as usize),
            _ => {}
        }
    }
    all_entries.sort();
    all_entries.dedup();

    let is_init_kfunc = |name: &str| {
        matches!(
            name,
            "bpf_dynptr_from_skb"
                | "bpf_dynptr_from_xdp"
                | "bpf_dynptr_clone"
                | "bpf_dynptr_adjust"
        )
    };

    let mut out: HashSet<usize> = HashSet::new();
    for &start in &entries {
        let end = all_entries
            .iter()
            .find(|&&pc| pc > start)
            .copied()
            .unwrap_or(prog.instrs.len());
        let body = &prog.instrs[start..end.min(prog.instrs.len())];
        let mut bad = false;
        for insn in body {
            match insn {
                Instr::Call { kind } => match *kind {
                    CallKind::Helper { id } => {
                        if id == constants::BPF_DYNPTR_FROM_MEM
                            || id == constants::BPF_RINGBUF_RESERVE_DYNPTR
                        {
                            bad = true;
                            break;
                        }
                    }
                    CallKind::Kfunc { btf_id, .. } => {
                        if let Some(name) = btf.kfunc_name(btf_id)
                            && is_init_kfunc(name)
                        {
                            bad = true;
                            break;
                        }
                    }
                },
                // Conservative: a CallRel to a global subprog could re-init
                // through a stack-passed dynptr ptr. We don't transitively
                // scan; treat any CallRel as taint. Cbs in our corpus that
                // reach the test cases of interest don't make CallRel.
                Instr::CallRel { .. } => {
                    bad = true;
                    break;
                }
                _ => {}
            }
        }
        if bad {
            out.insert(start);
        }
    }
    out
}

/// Per-cb-subprog set of byte offsets (relative to the cb's ctx-arg
/// pointer) the body may write through. Used by `cb_exit_propagate`
/// to widen across all branches when nr_loops > 1.
///
/// Strategy: for each cb-subprog entry (LD_IMM64 PSEUDO_FUNC target),
/// walk its body forward. Maintain the set of registers known to alias
/// the cb's ctx-arg pointer (R2 for bpf_loop / for_each_map_elem /
/// user_ringbuf_drain, R3 for find_vma — but the kernel routes the
/// caller's ctx into the cb's R2 in *all four* (cb's first non-index
/// arg). For simplicity, seed from {R1, R2, R3, R4, R5} so any of the
/// cb's typed args is treated as a candidate ctx-pointer; we further
/// narrow by only collecting offsets through stores via Mov-aliased
/// regs originating from R2 specifically. Cross-call clobber of
/// R0..R5 invalidates regs not preserved by helpers.
///
/// Misses we accept: register-arithmetic on the ctx pointer
/// (`R = R2 + 8; *R = …`), spill/fill, or stores via a stack-loaded
/// pointer (cb stores ctx to its own stack and loads it back). Any
/// such cb body simply gets a smaller offset set; widening still
/// fires for the offsets we DID detect, and the diff-based snapshot
/// path remains as the fallback for everything else.
pub fn compute_cb_body_store_offsets(prog: &crate::ast::Program) -> HashMap<usize, HashSet<i16>> {
    use crate::analysis::machine::reg::Reg;
    use crate::ast::{Instr, MapLoadKind, Operand};

    let mut entries: Vec<usize> = Vec::new();
    for insn in &prog.instrs {
        if let Instr::LoadMap {
            kind: MapLoadKind::PseudoFunc { subprog_pc },
            ..
        } = insn
        {
            entries.push(*subprog_pc as usize);
        }
    }
    entries.sort();
    entries.dedup();

    let mut all_entries: Vec<usize> = vec![0];
    for insn in &prog.instrs {
        match insn {
            Instr::CallRel { target } => all_entries.push(*target),
            Instr::LoadMap {
                kind: MapLoadKind::PseudoFunc { subprog_pc },
                ..
            } => all_entries.push(*subprog_pc as usize),
            _ => {}
        }
    }
    all_entries.sort();
    all_entries.dedup();

    let mut out: HashMap<usize, HashSet<i16>> = HashMap::new();
    for &start in &entries {
        let end = all_entries
            .iter()
            .find(|&&pc| pc > start)
            .copied()
            .unwrap_or(prog.instrs.len());
        let body = &prog.instrs[start..end.min(prog.instrs.len())];

        // Reg-aliasing scan. We seed `aliases` with R2 only (the cb's
        // ctx-pointer arg position for bpf_loop / for_each / user_ringbuf
        // — find_vma also uses the cb's R3 but the cb body's idiom there
        // is identical: ctx is one of the typed args). Adding R3..R5
        // here would broaden over-aggressively and risk widening
        // unrelated stack regions on other tests; leaving R2-only is
        // sound and closes the corpus FA without regressions seen so far.
        let mut aliases: HashSet<Reg> = HashSet::new();
        aliases.insert(Reg::R2);
        let mut offsets: HashSet<i16> = HashSet::new();
        for insn in body {
            match insn {
                Instr::Alu {
                    op: crate::ast::AluOp::Mov,
                    dst,
                    src: Operand::Reg(src_reg),
                    ..
                } => {
                    if aliases.contains(src_reg) {
                        aliases.insert(*dst);
                    } else {
                        // Mov from a non-alias clobbers any prior alias on dst.
                        aliases.remove(dst);
                    }
                }
                Instr::Alu { dst, .. } => {
                    // Any other ALU op breaks the alias on dst (we don't
                    // track ptr-arithmetic).
                    aliases.remove(dst);
                }
                Instr::Load { dst, .. } | Instr::LoadMap { dst, .. } => {
                    aliases.remove(dst);
                }
                Instr::Store { base, off, .. } => {
                    if aliases.contains(base) {
                        offsets.insert(*off);
                    }
                }
                Instr::Call { .. } => {
                    // Helper / kfunc calls clobber R0..R5. R6..R9 are
                    // callee-saved (preserved). Drop R0..R5 from aliases.
                    for r in [Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
                        aliases.remove(&r);
                    }
                }
                Instr::CallRel { .. } => {
                    // Callee may write through any stack-passed pointer
                    // we lose track of. Conservatively drop all aliases.
                    aliases.clear();
                }
                // Don't break on Exit — the cb body has multiple
                // basic blocks (one per branch) terminating in their
                // own Exit. We need to scan ALL of them. The body
                // range is bounded by the next subprog entry, so we
                // won't wander into another subprog.
                Instr::Exit => {}
                _ => {}
            }
        }
        if !offsets.is_empty() {
            out.insert(start, offsets);
        }
    }
    out
}
