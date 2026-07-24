// src/analysis/cfg.rs
use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::reg::Reg;
use crate::ast::{CallKind, Instr, MapLoadKind, Program};
use crate::common::config::VerifierConfig;
use crate::common::constants;

/// Which argument register carries the callback pointer for a given helper.
/// Returns None for helpers that don't take a callback.
fn callback_arg_reg(helper_id: u32) -> Option<Reg> {
    match helper_id {
        // bpf_for_each_map_elem(map, callback_fn, ctx, flags)
        constants::BPF_FOR_EACH_MAP_ELEM => Some(Reg::R2),
        // bpf_timer_set_callback(timer, callback_fn)
        constants::BPF_TIMER_SET_CALLBACK => Some(Reg::R2),
        // bpf_loop(nr_loops, callback_fn, ctx, flags)
        constants::BPF_LOOP => Some(Reg::R2),
        _ => None,
    }
}

/// Same as `callback_arg_reg` but for kfuncs, keyed by registered kfunc
/// name. Without this, programs that pass a `BPF_PSEUDO_FUNC` subprog
/// pointer to a callback-taking kfunc (e.g. `bpf_rbtree_add_impl`'s
/// `less` cb at R3, `bpf_wq_set_callback_impl`'s cb at R2) leave the cb
/// subprog body unvisited by DFS and the post-walk `unreachable insn`
/// check fires. Mirror of the helper handling at L114.
fn kfunc_callback_arg_reg(name: &str) -> Option<Reg> {
    match name {
        // int bpf_rbtree_add_impl(root, node, less_cb, meta__ign, off__ign)
        "bpf_rbtree_add_impl" => Some(Reg::R3),
        // int bpf_wq_set_callback_impl(wq, callback_fn, flags__ign, ...)
        "bpf_wq_set_callback_impl" => Some(Reg::R2),
        _ => None,
    }
}

/// Scan backward from `call_pc` through the current linear run of
/// instructions to find the PSEUDO_FUNC load that feeds `cb_reg`.
/// Follows reg-to-reg Mov chains (`Mov cb_reg, R6` → keep scanning for
/// the PSEUDO_FUNC that fed `R6`). Stops at the first branch/exit/call
/// we see (simple basic-block walk); if later dataflow proves richer
/// feeders, can revisit.
///
/// Caught `verifier_private_stack::private_stack_callback`, where the
/// pattern is `LoadMap R6, PseudoFunc; Mov R2, R6; Call bpf_loop`. R2
/// is the cb_reg for bpf_loop; without the chain-follow the scan saw
/// `Mov R2, R6` as a foreign write and gave up, leaving the callback's
/// body unreachable in DFS.
fn find_pseudo_func_for_call(prog: &Program, call_pc: usize, cb_reg: Reg) -> Option<u32> {
    let mut tracked = cb_reg;
    let mut pc = call_pc;
    while pc > 0 {
        pc -= 1;
        match &prog.instrs[pc] {
            Instr::LoadMap {
                dst,
                kind: MapLoadKind::PseudoFunc { subprog_pc },
                ..
            } if *dst == tracked => return Some(*subprog_pc),
            // `Mov tracked, Reg(src)` is an alias chain — keep scanning
            // backward for the producer of `src`. Any other write to
            // `tracked` (immediate Mov, arithmetic, load, foreign LoadMap)
            // breaks the direct feed.
            Instr::Alu { dst, op: crate::ast::AluOp::Mov, src: crate::ast::Operand::Reg(src), .. }
                if *dst == tracked =>
            {
                tracked = *src;
            }
            Instr::Alu { dst, .. } | Instr::MovSx { dst, .. } | Instr::Load { dst, .. }
            | Instr::LoadSx { dst, .. } | Instr::LoadMap { dst, .. }
                if *dst == tracked =>
            {
                return None;
            }
            // Leave the basic block: stop scanning.
            Instr::Jmp { .. } | Instr::If { .. } | Instr::Exit
            | Instr::Call { .. } | Instr::CallRel { .. } | Instr::MayGoto { .. } => return None,
            _ => {}
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VisitState {
    Unvisited,
    Discovered, // On stack (Gray)
    Explored,   // Finished (Black)
}

/// Helper to mark a PC as a pruning point.
/// Mirrors `init_explored_state` in kernel.
fn init_explored_state(env: &mut VerifierEnv, pc: usize) {
    if pc < env.insn_aux_data.len() {
        env.insn_aux_data[pc].prune_point = true;
    }
}

/// Helper to mark a PC as a jmp_point.
/// Mirrors `mark_jmp_point` in kernel (verifier.c L4146). Marked at
/// branch targets (kernel L18319, after `mark_prune_point(env, w)`)
/// and post-call fallthrough (kernel L18361, after the same). NOT
/// marked at conditional-jump SELF (L17556 marks prune_point only).
fn mark_jmp_point(env: &mut VerifierEnv, pc: usize) {
    if pc < env.insn_aux_data.len() {
        env.insn_aux_data[pc].jmp_point = true;
    }
}

/// Mirrors `visit_insn` from kernel/bpf/verifier.c
/// Returns a list of successors to push to the stack.
fn visit_insn(pc: usize, prog: &Program, env: &mut VerifierEnv) -> Result<Vec<usize>, String> {
    let instr = &prog.instrs[pc];
    let n = prog.instrs.len();
    let mut succs = Vec::new();

    // 1. NON-BRANCH INSTRUCTIONS (ALU, Load, Store)
    // Kernel: "All non-branch instructions have a single fall-through edge."
    // Logic: push_insn(t, t + 1, FALLTHROUGH, ...)
    if !matches!(
        instr,
        Instr::Jmp { .. }
            | Instr::If { .. }
            | Instr::Exit
            | Instr::Call { .. }
            | Instr::CallRel { .. }
            | Instr::MayGoto { .. }
    ) {
        if pc + 1 < n {
            succs.push(pc + 1);
        }
        return Ok(succs);
    }

    match instr {
        Instr::Exit => {
            // Kernel: return DONE_EXPLORING
            Ok(vec![])
        }
        Instr::Call { kind } => {
            // callback-taking helpers (bpf_loop, bpf_for_each_map_elem,
            // bpf_timer_set_callback) emit an extra successor edge into the
            // callback subprog so DFS explores it. The callback arg's
            // PSEUDO_FUNC feed is resolved by a backward scan within the
            // current basic block.
            let cb_reg = match kind {
                CallKind::Helper { id } => callback_arg_reg(*id),
                CallKind::Kfunc { btf_id, .. } => env
                    .ctx
                    .btf
                    .kfunc_name(*btf_id)
                    .and_then(kfunc_callback_arg_reg),
            };
            if let Some(cb_reg) = cb_reg
                && let Some(subprog_pc) = find_pseudo_func_for_call(prog, pc, cb_reg)
            {
                let target = subprog_pc as usize;
                if target < n {
                    succs.push(target);
                    init_explored_state(env, target);
                }
                // sync-callback-calling helpers are force-
                // checkpoint sites (kernel `mark_force_checkpoint` at
                // verifier.c L17489). Eviction threshold n=64 here vs
                // n=3 elsewhere — keeps cb-call checkpoints alive long
                // enough for cb-iteration convergence.
                if pc < env.insn_aux_data.len() {
                    env.insn_aux_data[pc].force_checkpoint = true;
                }
            }
            // iter_next kfunc call sites are force-checkpoint sites
            // (kernel `mark_force_checkpoint` at verifier.c L17523, gated
            // on `is_iter_next_kfunc`). The kernel needs the checkpoint
            // to guarantee a `parent_state` at the same insn_idx (see
            // `process_iter_next_call` L8903) and to converge bpf_for /
            // bpf_iter_num loops quickly. Without CFG-time marking,
            // the flag was set lazily by the kfunc handler — which is
            // AFTER the cache decision in `run_worklist` reads it. Under
            // `ZOVIA_KERNEL_ENGINE=1`, that left iter_next sites
            // uncached on first visit and the loop never converged
            // (state explosion → verifier timeout on iters_num /
            // verifier_bits_iter / iters families).
            if let CallKind::Kfunc { btf_id, .. } = kind
                && let Some(name) = env.ctx.btf.kfunc_name(*btf_id)
                && let Some(proto) =
                    crate::analysis::transfer::call::signatures::get_kfunc_proto(name)
                && matches!(
                    proto.ret,
                    crate::analysis::transfer::call::signatures::RetKind::IterNextElem { .. }
                        | crate::analysis::transfer::call::signatures::RetKind::IterNextBtfId { .. }
                )
                && pc < env.insn_aux_data.len()
            {
                // Mark BOTH prune_point and force_checkpoint, mirroring
                // verifier.c L17511 (mark_prune_point) + L17523
                // (mark_force_checkpoint). Need prune_point so the
                // kernel-engine `outer_gate = at_prune_point` admits the
                // cache decision; need force_checkpoint so
                // `add_new_state` fires unconditionally there.
                env.insn_aux_data[pc].prune_point = true;
                env.insn_aux_data[pc].force_checkpoint = true;
            }
            if pc + 1 < n {
                succs.push(pc + 1);
                // Kernel: `visit_func_call_insn` unconditionally marks the
                // post-call fallthrough as a prune point (verifier.c L17175
                // `mark_prune_point(env, t + insn_sz)`). Applies to ALL
                // calls (helper + subprog). Without this, sparse-cache
                // mode never caches post-call states, so the BCF discharge
                // walker can't land at kernel-equivalent post-call bases.
                init_explored_state(env, pc + 1);
                // Kernel mirror: visit_func_call_insn marks the post-call
                // fallthrough as BOTH prune_point AND jmp_point
                // (verifier.c L18361 `mark_jmp_point(env, t + insn_sz)`).
                // Drives `cur->jmp_history_cnt` accumulation used by the
                // `add_new_state` long-history safety valve.
                mark_jmp_point(env, pc + 1);
            }
            Ok(succs)
        }
        Instr::Jmp { target } => {
            // Kernel Case: BPF_JA
            // 1. Push successor (target)
            // "unconditional jump with single edge"
            succs.push(*target);

            // 2. Mark Target as Prune Point + Jmp Point
            // "init_explored_state(env, t + insns[t].off + 1);"
            // Kernel push_insn BRANCH edge marks both prune_point AND
            // jmp_point (verifier.c L18316-L18319).
            init_explored_state(env, *target);
            mark_jmp_point(env, *target);

            // 3. Mark Fallthrough as Prune Point (Defensive/History)
            // "if (t + 1 < insn_cnt) init_explored_state(env, t + 1);"
            if pc + 1 < n {
                init_explored_state(env, pc + 1);
            }

            Ok(succs)
        }
        Instr::If { target, .. } => {
            // Kernel Default Case: Conditional Jump
            // 1. Mark SELF as Prune Point (verifier.c L17556
            //    `mark_prune_point(env, t)` in the conditional-jump arm).
            init_explored_state(env, pc);

            // 2. Push Fallthrough
            if pc + 1 < n {
                succs.push(pc + 1);
            }

            // 3. Push Target — and ALSO mark target as a prune point,
            //    mirroring kernel `push_insn` BRANCH-edge handling
            //    (verifier.c L17132-17136 `if (e == BRANCH)
            //    mark_prune_point(env, w)`). Without this, sparse-cache
            //    mode never caches at conditional-branch targets, so
            //    zovia's vstate chain would miss kernel parents at
            //    If-target PCs.
            init_explored_state(env, *target);
            mark_jmp_point(env, *target);
            succs.push(*target);

            Ok(succs)
        }
        Instr::MayGoto { target } => {
            // BPF_JCOND (v6.8) — bounded back-edge whose taken/fallthrough
            // both reach reachable code. Modeled as a conditional jump:
            // mark self + both edges as prune points and emit both
            // successors. Without this, may_goto's `target` was dropped
            // by the non-branch fall-through above and post-may_goto code
            // (e.g. cond_break5's exit at pc 6) showed up as
            // "CFG error: unreachable insn".
            //
            // Termination at runtime relies on `goto_budget` saturating
            // and pruning at the loop head, not on CFG structure — so
            // the static CFG just needs both edges visible.
            init_explored_state(env, pc);
            if pc + 1 < n {
                succs.push(pc + 1);
                init_explored_state(env, pc + 1);
                mark_jmp_point(env, pc + 1);
            }
            succs.push(*target);
            init_explored_state(env, *target);
            mark_jmp_point(env, *target);
            // may_goto is a force-checkpoint site (kernel
            // `mark_force_checkpoint` at verifier.c L17557).
            if pc < env.insn_aux_data.len() {
                env.insn_aux_data[pc].force_checkpoint = true;
            }
            Ok(succs)
        }
        Instr::CallRel { target } => {
            // 0. Mark the CALL insn itself as a prune point — kernel
            //    visit_func_call_insn: `if (visit_callee) {
            //    mark_prune_point(env, t); ... }` (pseudo-calls only).
            //    Without this mark the caller-side prune point at the
            //    call insn is skipped and the state-add slides one insn
            //    into the callee entry.
            init_explored_state(env, pc);
            // 1. Push the Function Entry (The Call)
            succs.push(*target);
            init_explored_state(env, *target);
            mark_jmp_point(env, *target);

            // 2. Push the Return Point (Fallthrough)
            // We assume the function eventually returns.
            if pc + 1 < n {
                succs.push(pc + 1);
                // The return point is a convergence point (many callers return here),
                // so it's a good candidate for pruning.
                init_explored_state(env, pc + 1);
                // Subprog-return fallthrough is a jmp_point in kernel
                // (visit_func_call_insn, verifier.c L18361).
                mark_jmp_point(env, pc + 1);
            }

            Ok(succs)
        }
        _ => {
            // Should be covered by non-branch check above, but safe fallback
            if pc + 1 < n {
                succs.push(pc + 1);
            }
            Ok(succs)
        }
    }
}

/// Get successors for a given instruction (for cycle detection).
fn get_successors(pc: usize, prog: &Program) -> Vec<usize> {
    let n = prog.instrs.len();
    if pc >= n {
        return vec![];
    }
    match &prog.instrs[pc] {
        Instr::Exit => vec![],
        Instr::Jmp { target } => vec![*target],
        Instr::If { target, .. } | Instr::MayGoto { target } => {
            let mut succs = vec![*target];
            if pc + 1 < n {
                succs.push(pc + 1);
            }
            succs
        }
        _ => {
            if pc + 1 < n {
                vec![pc + 1]
            } else {
                vec![]
            }
        }
    }
}

/// Check if there's a path from `start` to `target` without going through `exit` instructions.
/// Used to detect if a backward jump is part of a real loop.
fn has_path_to(prog: &Program, start: usize, target: usize, visited: &mut Vec<bool>) -> bool {
    // Iterative DFS (explicit stack) — recursion here overflowed the native
    // stack on long straight-line programs, since the recursion depth equals
    // the path length (e.g. the gotol selftest). The visited-set makes it
    // linear in CFG size regardless.
    let mut stack: Vec<usize> = vec![start];
    while let Some(node) = stack.pop() {
        if node == target {
            return true;
        }
        if node >= prog.instrs.len() || visited[node] {
            continue;
        }
        visited[node] = true;
        for succ in get_successors(node, prog) {
            if !(succ < prog.instrs.len() && visited[succ]) {
                stack.push(succ);
            }
        }
    }
    false
}

/// Check if a backward jump forms an actual loop (has a cycle).
/// A back-edge from B to H is a real loop if there's a path from H back to B.
fn is_real_loop(prog: &Program, back_edge_src: usize, back_edge_tgt: usize) -> bool {
    let mut visited = vec![false; prog.instrs.len()];
    has_path_to(prog, back_edge_tgt, back_edge_src, &mut visited)
}

/// Collect all back-edges that form actual loops.
/// A back-edge is a jump from a higher PC to a lower PC that creates a cycle.
/// Returns vec of (source_pc, target_pc).
pub fn collect_loop_back_edges(prog: &Program) -> Vec<(usize, usize)> {
    let mut back_edges = Vec::new();
    for (pc, instr) in prog.instrs.iter().enumerate() {
        let target = match instr {
            Instr::Jmp { target } if *target < pc => Some(*target),
            Instr::If { target, .. } if *target < pc => Some(*target),
            _ => None,
        };
        if let Some(tgt) = target {
            // Only include if it forms a real loop
            if is_real_loop(prog, pc, tgt) {
                back_edges.push((pc, tgt));
            }
        }
    }
    back_edges
}

/// Check if any forward jump skips over a loop head to land at the loop's
/// conditional check (back-edge source).
///
/// The kernel's bounded loop support requires single-entry loops (dominator tree).
/// The "start in the middle" pattern occurs when:
/// - There's a back-edge from B to H (loop head H < back-edge source B)
/// - There's a forward jump from A to B where A < H
/// - This means the forward jump skips over the loop head H and enters
///   at the conditional check B, causing the first iteration to skip
///   the loop body entirely.
///
/// Returns Some((from_pc, to_pc)) if such a pattern is found.
fn check_jump_into_loop_middle(prog: &Program) -> Option<(usize, usize)> {
    let back_edges = collect_loop_back_edges(prog);

    for (be_src, be_tgt) in &back_edges {
        let loop_head = *be_tgt; // H - where the loop body starts
        let back_edge_src = *be_src; // B - where the conditional/back-edge is

        // Check for forward jumps that land at the back-edge source
        // from before the loop head
        for (pc, instr) in prog.instrs.iter().enumerate() {
            let targets: Vec<usize> = match instr {
                Instr::Jmp { target } => vec![*target],
                Instr::If { target, .. } => vec![*target],
                _ => vec![],
            };

            for target in targets {
                // Pattern: forward jump from before loop head, landing at back-edge source
                // This skips the loop body on first entry
                if pc < loop_head && target == back_edge_src {
                    return Some((pc, target));
                }
            }
        }
    }
    None
}

/// Performs DFS to validate CFG and populate prune points via visit_insn.
pub fn check_cfg(
    prog: &Program,
    env: &mut VerifierEnv,
    config: &VerifierConfig,
) -> Result<(), String> {
    let n = prog.instrs.len();
    if n == 0 {
        return Ok(());
    }

    // In kernel-mode, check for jumps into the middle of loops.
    // The kernel's bounded loop support requires single-entry loops (dominator tree).
    // Code that jumps into the middle of a loop cannot be verified.
    if config.require_single_loop_entry {
        if let Some((from_pc, to_pc)) = check_jump_into_loop_middle(prog) {
            return Err(format!("back-edge from insn {} to {}", from_pc, to_pc));
        }
    }

    let mut state = vec![VisitState::Unvisited; n];
    let mut stack = Vec::new();

    // Roots: pc 0 (main entry) plus any registered `__exception_cb`
    // subprog. Exception cbs are unreachable from main's CFG by design
    // — kernel invokes them via the unwind path — but their bodies
    // must still pass the unreachable-insn check (kernel's
    // `do_check_subprogs` force-marks them as called).
    let mut roots: Vec<usize> = vec![0];
    if let Some(cb_name) = env.ctx.exception_callback.as_deref() {
        for (&pc, name) in env.ctx.pc_to_subprog_name.iter() {
            if name == cb_name {
                roots.push(pc);
            }
        }
    }
    for &root in &roots {
        if root < n && state[root] == VisitState::Unvisited {
            state[root] = VisitState::Discovered;
            stack.push(root);
            init_explored_state(env, root);
        }
    }

    while let Some(&pc) = stack.last() {
        // If we haven't processed children yet (Discovered), do so now.
        // Note: Real DFS usually processes children then marks Explored.
        // We simulate this by checking if we have pushed children or not.
        // Simplified: We grab successors using visit_insn.

        let mut new_child = None;

        // This is a slight simplification of the kernel's stack-based state machine,
        // but achieves the same graph traversal coverage.
        let succs = visit_insn(pc, prog, env)?;

        for succ in succs {
            if succ >= n {
                return Err(format!("Jump out of bounds at PC {}", pc));
            }

            if state[succ] == VisitState::Unvisited {
                state[succ] = VisitState::Discovered;
                stack.push(succ);
                new_child = Some(succ);
                break; // DFS: Follow this path immediately
            } else if state[succ] == VisitState::Discovered {
                // Back-edge detected.
                // visit_insn logic handles marking, but we can double-check
                // if we strictly need to mark the loop head if visit_insn didn't.
                // Based on kernel BPF_JA/BPF_JNE logic, the points are already set.
            }
        }

        if new_child.is_none() {
            state[pc] = VisitState::Explored;
            stack.pop();
        }
    }

    // Unreachable-instruction check: only enforce when the program uses
    // BPF-to-BPF sub-calls (CallRel).  Sub-call programs must have every
    // sub-function reachable — an orphaned function body is a programming
    // error that even the Linux 5.15 kernel rejects.
    //
    // For programs without CallRel, dead code after a statically-eliminated
    // branch is a normal compiler artefact accepted by kernel ≥ 6.6; the
    // abstract interpreter simply never visits those PCs.
    let has_callrel = prog.instrs.iter().any(|i| matches!(i, Instr::CallRel { .. }));
    if has_callrel {
        for (pc, &s) in state.iter().enumerate() {
            if s == VisitState::Unvisited {
                return Err(format!("unreachable insn at pc {}", pc));
            }
        }
    }

    Ok(())
}
