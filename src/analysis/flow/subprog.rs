// src/analysis/flow/subprog.rs
//
// Subprogram analysis: structure validation and stack overflow checking

use crate::analysis::machine::reg::Reg;
use crate::ast::{AluOp, CallKind, Instr, Operand, Program, ProgramKind, Width};
use crate::common::constants;
use std::collections::{BTreeMap, BTreeSet, HashSet};

const MAX_BPF_STACK: u16 = 512;

#[derive(Debug, Clone)]
pub struct SubprogInfo {
    pub start_pc: usize,
    pub end_pc: usize,
    pub max_stack_depth: u16,
}

/// returns true if a program of `prog_kind` is eligible for the
/// v6.12+ private-stack feature. Mirrors `bpf_priv_stack_supported`
/// (kernel/bpf/verifier.c) — only program types that run with
/// preempt_disable / are NMI-safe (so the per-CPU private stack arena
/// is reentrant-safe) appear here.
///
/// Excludes any program whose call graph contains `bpf_tail_call`
/// (helper id 12): the kernel can't share the private-stack arena
/// across tail-called programs.
pub fn private_stack_eligible(prog_kind: ProgramKind, instrs: &[Instr]) -> bool {
    let prog_type_ok = matches!(
        prog_kind,
        ProgramKind::Kprobe
            | ProgramKind::Tracepoint
            | ProgramKind::PerfEvent
            | ProgramKind::RawTracepoint
            | ProgramKind::RawTracepointWritable
            | ProgramKind::StructOps
    );
    if !prog_type_ok {
        return false;
    }
    // Tail-call presence rules out private stack (kernel: same arena
    // can't survive a tail-call jump).
    !instrs.iter().any(|i| {
        matches!(
            i,
            Instr::Call {
                kind: CallKind::Helper { id }
            } if *id == constants::BPF_TAIL_CALL
        )
    })
}

#[derive(Debug, Clone)]
pub enum SubprogError {
    JumpOutOfRange {
        pc: usize,
        target: usize,
        start: usize,
        end: usize,
    },
    CallOutOfBounds {
        pc: usize,
        target: usize,
    },
    InvalidTerminator {
        pc: usize,
    },
    StackOverflow {
        pc: usize,
        combined: u16,
    },
    CallDepthExceeded {
        pc: usize,
        depth: usize,
    },
    RecursiveCall {
        pc: usize,
        target: usize,
    },
}

impl std::fmt::Display for SubprogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubprogError::JumpOutOfRange {
                pc,
                target,
                start,
                end,
            } => {
                write!(
                    f,
                    "jump out of range at pc {}: target {} is outside function scope [{}, {})",
                    pc, target, start, end
                )
            }
            SubprogError::CallOutOfBounds { pc, target } => {
                write!(f, "call out of bounds at pc {}: target {}", pc, target)
            }
            SubprogError::InvalidTerminator { pc } => {
                write!(f, "last insn at pc {} is not an exit or jmp", pc)
            }
            SubprogError::StackOverflow { pc, combined } => {
                write!(
                    f,
                    "combined stack size of {} at pc {} exceeds {}",
                    combined, pc, MAX_BPF_STACK
                )
            }
            SubprogError::CallDepthExceeded { pc, depth } => {
                write!(
                    f,
                    "call depth of {} at pc {} exceeds maximum of 8",
                    depth, pc
                )
            }
            SubprogError::RecursiveCall { pc, target } => {
                write!(f, "back-edge from insn {} to {}", pc, target)
            }
        }
    }
}

/// Analyze all subprograms and compute their max stack depths.
pub fn analyze_subprograms(instrs: &[Instr]) -> BTreeMap<usize, SubprogInfo> {
    let mut entries: Vec<usize> = vec![0];

    for insn in instrs {
        match insn {
            Instr::CallRel { target } => {
                if !entries.contains(target) {
                    entries.push(*target);
                }
            }
            // `LD_IMM64 BPF_PSEUDO_FUNC` materializes a function pointer
            // for callbacks — bpf_loop / bpf_for_each_map_elem (sync) and
            // bpf_timer_set_callback / bpf_wq_set_callback_impl (async).
            // Those subprogs are not reached via CallRel from the caller's
            // body, but their PCs still need to be subprog boundaries:
            // otherwise their body bleeds into the preceding subprog's
            // range and any CallRel inside (e.g. `subprog1(key)` inside
            // an async timer cb) is misattributed as a back-edge of the
            // outer subprog. Kernel `verifier.c` ~L10477 handles async
            // callbacks via `push_async_cb` (separate verifier root); we
            // approximate by giving each callback target its own subprog
            // boundary in the static call-chain analysis.
            Instr::LoadMap {
                kind: crate::ast::MapLoadKind::PseudoFunc { subprog_pc },
                ..
            } => {
                let pc = *subprog_pc as usize;
                if !entries.contains(&pc) {
                    entries.push(pc);
                }
            }
            _ => {}
        }
    }
    entries.sort();

    let mut subprogs = BTreeMap::new();

    for (i, &start_pc) in entries.iter().enumerate() {
        let end_pc = entries.get(i + 1).copied().unwrap_or(instrs.len());
        let max_stack_depth = compute_max_stack_depth(&instrs[start_pc..end_pc]);

        subprogs.insert(
            start_pc,
            SubprogInfo {
                start_pc,
                end_pc,
                max_stack_depth,
            },
        );
    }

    subprogs
}

/// Names of kfuncs the kernel registers with `KF_SLEEPABLE` (i.e.
/// callable only from sleepable context — equivalent to MIGHT_SLEEP for
/// the global-subprog static walk). Independent of `get_kfunc_proto`'s
/// `MIGHT_SLEEP` flag, since several sleepable kfuncs aren't yet on the
/// proto path. Closes the irq/preempt FA tests
/// (`irq_sleepable_global_subprog_indirect`,
/// `irq_sleepable_helper_global_subprog`,
/// `preempt_global_sleepable_subprog_indirect`) where the test bodies
/// call `bpf_copy_from_user_str` (kfunc, not yet proto'd) inside an
/// irq/preempt-disabled region via a global subprog.
fn kfunc_name_might_sleep(name: &str) -> bool {
    matches!(
        name,
        "bpf_copy_from_user_str" | "bpf_copy_from_user_task" | "bpf_copy_from_user_task_str"
    )
}

/// Compute the set of subprog start-PCs whose body — directly or
/// transitively via CallRel / PSEUDO_FUNC callbacks — invokes a
/// MIGHT_SLEEP helper or kfunc. Mirrors the kernel verifier's static
/// call-graph walk used to gate global-subprog calls under irq- /
/// preempt-disabled regions ("global functions that may sleep are not
/// allowed in non-sleepable context").
///
/// Independent of data flow: a may-sleep call inside a dead branch
/// still marks the subprog. Kernel does the same (`fn->might_sleep`
/// is structural, not path-sensitive).
pub fn compute_may_sleep_subprogs(
    instrs: &[Instr],
    subprogs: &BTreeMap<usize, SubprogInfo>,
    btf: &crate::parsing::btf::BtfContext,
) -> HashSet<usize> {
    use crate::analysis::transfer::call::signatures::{
        CallFlags, get_helper_proto, get_kfunc_proto,
    };
    use crate::ast::MapLoadKind;

    // Direct may-sleep + outgoing CallRel/PseudoFunc edges per subprog.
    let mut direct: HashSet<usize> = HashSet::new();
    let mut edges: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();

    for (&start_pc, info) in subprogs.iter() {
        let mut callees = BTreeSet::new();
        for insn in &instrs[start_pc..info.end_pc] {
            match insn {
                Instr::Call {
                    kind: CallKind::Helper { id },
                    ..
                } => {
                    if let Some(proto) = get_helper_proto(*id)
                        && proto.flags.contains(CallFlags::MIGHT_SLEEP)
                    {
                        direct.insert(start_pc);
                    }
                }
                Instr::Call {
                    kind: CallKind::Kfunc { btf_id, .. },
                    ..
                } => {
                    let name = btf.kfunc_name(*btf_id);
                    let proto_might_sleep = name
                        .and_then(get_kfunc_proto)
                        .map(|p| p.flags.contains(CallFlags::MIGHT_SLEEP))
                        .unwrap_or(false);
                    let name_might_sleep = name.map(kfunc_name_might_sleep).unwrap_or(false);
                    if proto_might_sleep || name_might_sleep {
                        direct.insert(start_pc);
                    }
                }
                Instr::CallRel { target } => {
                    callees.insert(*target);
                }
                Instr::LoadMap {
                    kind: MapLoadKind::PseudoFunc { subprog_pc },
                    ..
                } => {
                    callees.insert(*subprog_pc as usize);
                }
                _ => {}
            }
        }
        edges.insert(start_pc, callees);
    }

    // Transitive closure: a subprog may-sleep if any callee may-sleep.
    let mut may_sleep = direct.clone();
    let mut changed = true;
    while changed {
        changed = false;
        for (&pc, callees) in edges.iter() {
            if may_sleep.contains(&pc) {
                continue;
            }
            if callees.iter().any(|c| may_sleep.contains(c)) {
                may_sleep.insert(pc);
                changed = true;
            }
        }
    }
    may_sleep
}

/// Per-subprog overhead the interpreter reserves at the bottom of the
/// frame for `may_goto`'s iteration counter. Mirrors the kernel constant
/// `BPF_MAY_GOTO_DEPTH` used in `check_max_stack_depth_subprog` —
/// a subprog containing any `may_goto` instruction needs an extra 8
/// bytes of stack on top of its directly-accessed depth, so the
/// effective per-subprog cap drops from 512 to 504.
const MAY_GOTO_STACK_EXTRA: u16 = 8;

/// Compute the maximum stack depth accessed by a sequence of Instrs.
///
/// Tracks a tiny "register holds R10 + const" alias table so accesses
/// through derived stack pointers (`r1 = r10; r1 += -512; *(u32 *)(r1 + 0) = …`)
/// count toward depth — the kernel's pre-walk does the equivalent via
/// per-instruction `update_stack_depth` calls, and the FALSE_ACCEPT for
/// `verifier_stack_ptr::stack_check_size_512_with_may_goto` was caused
/// by missing exactly this idiom.
fn compute_max_stack_depth(instrs: &[Instr]) -> u16 {
    let mut max_depth: u16 = 0;
    let mut has_may_goto = false;

    // Per-register: Some(off) means "this reg currently holds R10 + off"
    // (off is signed so we can represent above-frame offsets, though the
    // kernel rejects positive R10 offsets elsewhere). None ⇒ unknown /
    // not a stack alias. R10 itself is always offset 0.
    let mut alias: [Option<i64>; Reg::ALL.len()] = [None; { Reg::ALL.len() }];
    alias[Reg::R10.idx()] = Some(0);

    let track_access =
        |alias: &[Option<i64>; Reg::ALL.len()], base: Reg, off: i16, max_depth: &mut u16| {
            if let Some(base_off) = alias[base.idx()] {
                let total = base_off + off as i64;
                if total < 0 {
                    let depth = (-total) as u64;
                    if depth <= u16::MAX as u64 {
                        *max_depth = (*max_depth).max(depth as u16);
                    }
                }
            }
        };

    for insn in instrs {
        match insn {
            Instr::MayGoto { .. } => {
                has_may_goto = true;
            }
            Instr::Store { base, off, .. } => {
                track_access(&alias, *base, *off, &mut max_depth);
            }
            Instr::StoreRel { base, off, .. } => {
                track_access(&alias, *base, *off, &mut max_depth);
            }
            Instr::Load { base, off, dst, .. } => {
                track_access(&alias, *base, *off, &mut max_depth);
                // Load clobbers dst's alias (loaded value is data, not a
                // stack pointer — even if base was a stack alias).
                alias[dst.idx()] = None;
            }
            Instr::LoadSx { base, off, dst, .. } => {
                track_access(&alias, *base, *off, &mut max_depth);
                alias[dst.idx()] = None;
            }
            Instr::LoadAcq { base, off, dst, .. } => {
                track_access(&alias, *base, *off, &mut max_depth);
                alias[dst.idx()] = None;
            }
            Instr::Atomic { base, off, .. } => {
                track_access(&alias, *base, *off, &mut max_depth);
            }
            // Alias propagation: only on 64-bit ALU (32-bit truncates the
            // pointer half; the kernel rejects stack accesses through
            // 32-bit-truncated pointers anyway).
            Instr::Alu {
                width,
                op,
                dst,
                src,
            } => {
                if *dst == Reg::R10 {
                    // Defensive: R10 is never written; preserve its 0 alias.
                    continue;
                }
                if *width != Width::W64 {
                    alias[dst.idx()] = None;
                    continue;
                }
                match op {
                    AluOp::Mov => match src {
                        Operand::Reg(r) => {
                            alias[dst.idx()] = alias[r.idx()];
                        }
                        Operand::Imm(_) => {
                            alias[dst.idx()] = None;
                        }
                    },
                    AluOp::Add => match src {
                        Operand::Imm(k) => {
                            if let Some(o) = alias[dst.idx()] {
                                alias[dst.idx()] = Some(o + *k);
                            }
                        }
                        Operand::Reg(_) => {
                            alias[dst.idx()] = None;
                        }
                    },
                    AluOp::Sub => match src {
                        Operand::Imm(k) => {
                            if let Some(o) = alias[dst.idx()] {
                                alias[dst.idx()] = Some(o - *k);
                            }
                        }
                        Operand::Reg(_) => {
                            alias[dst.idx()] = None;
                        }
                    },
                    _ => {
                        alias[dst.idx()] = None;
                    }
                }
            }
            Instr::MovSx { dst, .. } => {
                alias[dst.idx()] = None;
            }
            Instr::Endian { dst, .. } => {
                alias[dst.idx()] = None;
            }
            Instr::LoadPacket { .. } => {
                // BPF_LD_ABS / BPF_LD_IND clobber R0..R5.
                for r in [Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
                    alias[r.idx()] = None;
                }
            }
            Instr::LoadMap { dst, .. } => {
                alias[dst.idx()] = None;
            }
            Instr::Call { .. } | Instr::CallRel { .. } => {
                // Helper / subprog call: R0 = retval (scalar/ptr, never
                // stack alias); R1..R5 are clobbered.
                for r in [Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
                    alias[r.idx()] = None;
                }
            }
            Instr::If { .. } | Instr::Jmp { .. } | Instr::Exit => {
                // Control flow: linear walk doesn't model joins; conservatively
                // accept that a register's alias may be inconsistent across
                // branches. We accept some imprecision (a positive over-
                // approximation of stack usage) in exchange for catching the
                // common `r10 += -K; deref` idiom.
            }
        }
    }

    if has_may_goto {
        max_depth = max_depth.saturating_add(MAY_GOTO_STACK_EXTRA);
    }

    max_depth
}

/// Validate subprogram structure: jump bounds and terminators.
/// Moved from cfg.rs
pub fn check_subprogs(prog: &Program) -> Result<(), SubprogError> {
    // 1. Identify all function entry points
    let mut func_starts = BTreeSet::new();
    func_starts.insert(0);

    for insn in &prog.instrs {
        if let Instr::CallRel { target } = insn {
            func_starts.insert(*target);
        }
    }

    let starts: Vec<usize> = func_starts.into_iter().collect();

    // 2. Validate each function
    for (i, &start) in starts.iter().enumerate() {
        let end = starts.get(i + 1).cloned().unwrap_or(prog.instrs.len());

        // A. Validate Instrs within the function
        for pc in start..end {
            let insn = &prog.instrs[pc];
            let is_local = |t: usize| t >= start && t < end;

            match insn {
                Instr::Jmp { target } => {
                    if !is_local(*target) {
                        return Err(SubprogError::JumpOutOfRange {
                            pc,
                            target: *target,
                            start,
                            end,
                        });
                    }
                }
                Instr::If { target, .. } => {
                    if !is_local(*target) {
                        return Err(SubprogError::JumpOutOfRange {
                            pc,
                            target: *target,
                            start,
                            end,
                        });
                    }
                }
                Instr::CallRel { target } => {
                    if *target >= prog.instrs.len() {
                        return Err(SubprogError::CallOutOfBounds {
                            pc,
                            target: *target,
                        });
                    }
                }
                _ => {}
            }
        }

        // B. Validate the function terminator
        if end > 0 {
            let last_pc = end - 1;
            let last_insn = &prog.instrs[last_pc];

            let is_terminator = matches!(last_insn, Instr::Jmp { .. } | Instr::Exit);

            if !is_terminator {
                return Err(SubprogError::InvalidTerminator { pc: last_pc });
            }
        }
    }

    Ok(())
}

/// Check that no call chain would cause stack overflow.
///
/// when `private_stack_enabled` is true AND `prog_kind` is in the
/// kernel's eligibility set (see `private_stack_eligible`), each subprog
/// gets its own stack arena — the cumulative call-chain budget is not
/// enforced; only each subprog's own ≤512-byte limit. This mirrors v6.12
/// `bpf_priv_stack_supported` semantics.
pub fn check_stack_overflow(
    prog: &Program,
    prog_kind: ProgramKind,
    private_stack_enabled: bool,
) -> Result<(), SubprogError> {
    let subprogs = analyze_subprograms(&prog.instrs);

    if subprogs.is_empty() {
        return Ok(());
    }

    let private_stack = private_stack_enabled && private_stack_eligible(prog_kind, &prog.instrs);

    check_call_chain(
        prog,
        &subprogs,
        0,
        0,
        1,
        None,
        private_stack,
        &mut HashSet::new(),
    )?;

    // Kernel-aligned: `check_max_stack_depth` (verifier.c v6.15 ~L6627)
    // also walks every `is_async_cb` subprog as its own root, because async
    // callbacks (registered via `bpf_timer_set_callback`) execute on a
    // fresh kernel stack — their chain depth must fit ≤MAX_BPF_STACK on
    // its own, not added to main's. Without this, programs whose async-cb
    // chain exceeds 512B but whose main path fits silently passed
    // (e.g. async_stack_depth.c::async_call_root_check).
    //
    // Identify async cbs via static scan: any `LoadMap{PseudoFunc{pc}}`
    // whose result feeds R2 of a `bpf_timer_set_callback` helper call
    // marks `pc` as an async-cb root. (Sync-cb helpers like bpf_loop /
    // bpf_for_each_map_elem use the same LD_IMM64 mechanism but execute
    // on the caller's stack — kernel does NOT root them, so we don't
    // either.)
    for &root in &collect_async_cb_roots(&prog.instrs) {
        check_call_chain(
            prog,
            &subprogs,
            root,
            0,
            1,
            None,
            private_stack,
            &mut HashSet::new(),
        )?;
    }
    Ok(())
}

/// Static scan: collect subprog entry PCs that are registered as async
/// callbacks via `bpf_timer_set_callback`. Mirrors the kernel marking
/// `subprog_info[idx].is_async_cb = true` in `set_timer_callback_state`
/// (verifier.c v6.15 ~L10481).
///
/// Heuristic: walk the instruction stream tracking, per register, the
/// most recent `LoadMap{PseudoFunc{pc}}` written to it. When a
/// `Call{Helper{BPF_TIMER_SET_CALLBACK}}` is reached, the value in R2
/// at that point identifies the cb subprog. Any write to R2 that isn't
/// such a load clears the alias.
fn collect_async_cb_roots(instrs: &[Instr]) -> BTreeSet<usize> {
    let mut roots = BTreeSet::new();
    let mut pseudofunc_alias: [Option<usize>; Reg::ALL.len()] = [None; { Reg::ALL.len() }];

    let clear_dst = |alias: &mut [Option<usize>; Reg::ALL.len()], dst: Reg| {
        alias[dst.idx()] = None;
    };

    for insn in instrs {
        match insn {
            Instr::LoadMap {
                dst,
                kind: crate::ast::MapLoadKind::PseudoFunc { subprog_pc },
                ..
            } => {
                pseudofunc_alias[dst.idx()] = Some(*subprog_pc as usize);
            }
            Instr::LoadMap { dst, .. } => clear_dst(&mut pseudofunc_alias, *dst),
            Instr::Alu {
                op: AluOp::Mov,
                dst,
                src: Operand::Reg(s),
                width: Width::W64,
            } => {
                pseudofunc_alias[dst.idx()] = pseudofunc_alias[s.idx()];
            }
            Instr::Alu { dst, .. } => clear_dst(&mut pseudofunc_alias, *dst),
            Instr::MovSx { dst, .. }
            | Instr::Endian { dst, .. }
            | Instr::Load { dst, .. }
            | Instr::LoadSx { dst, .. }
            | Instr::LoadAcq { dst, .. } => clear_dst(&mut pseudofunc_alias, *dst),
            Instr::Call {
                kind: CallKind::Helper { id },
            } => {
                if *id == constants::BPF_TIMER_SET_CALLBACK
                    && let Some(target) = pseudofunc_alias[Reg::R2.idx()]
                {
                    roots.insert(target);
                }
                // Helper clobbers R0..R5.
                for r in [Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
                    pseudofunc_alias[r.idx()] = None;
                }
            }
            Instr::Call { .. } | Instr::CallRel { .. } => {
                for r in [Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
                    pseudofunc_alias[r.idx()] = None;
                }
            }
            Instr::LoadPacket { .. } => {
                for r in [Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
                    pseudofunc_alias[r.idx()] = None;
                }
            }
            _ => {}
        }
    }

    roots
}

#[allow(clippy::too_many_arguments)]
fn check_call_chain(
    prog: &Program,
    subprogs: &BTreeMap<usize, SubprogInfo>,
    entry_pc: usize,
    depth_so_far: u16,
    call_depth: usize,        // number of frames
    caller_pc: Option<usize>, // PC of the CallRel that invoked us (None for root)
    private_stack: bool,      // whole-program private-stack mode
    visiting: &mut HashSet<usize>,
) -> Result<(), SubprogError> {
    // Check call depth first
    if call_depth > constants::BPF_MAX_CALL_FRAMES {
        return Err(SubprogError::CallDepthExceeded {
            pc: caller_pc.unwrap_or(entry_pc),
            depth: call_depth,
        });
    }

    // Detect recursive calls: if entry_pc is already being visited,
    // we have a cycle in the call graph → reject as back-edge.
    if !visiting.insert(entry_pc) {
        return Err(SubprogError::RecursiveCall {
            pc: caller_pc.unwrap_or(entry_pc),
            target: entry_pc,
        });
    }

    let info = match subprogs.get(&entry_pc) {
        Some(info) => info,
        None => {
            visiting.remove(&entry_pc);
            return Ok(());
        }
    };

    // under private_stack, each subprog has its own arena —
    // validate this subprog's depth against MAX_BPF_STACK alone and
    // do NOT add to depth_so_far. Otherwise (legacy / ineligible
    // program) accumulate as before.
    let new_depth = if private_stack {
        if info.max_stack_depth > MAX_BPF_STACK {
            return Err(SubprogError::StackOverflow {
                pc: entry_pc,
                combined: info.max_stack_depth,
            });
        }
        depth_so_far
    } else {
        let nd = depth_so_far + info.max_stack_depth;
        if nd > MAX_BPF_STACK {
            return Err(SubprogError::StackOverflow {
                pc: entry_pc,
                combined: nd,
            });
        }
        nd
    };

    for pc in info.start_pc..info.end_pc {
        if let Instr::CallRel { target } = &prog.instrs[pc] {
            check_call_chain(
                prog,
                subprogs,
                *target,
                new_depth,
                call_depth + 1,
                Some(pc),
                private_stack,
                visiting,
            )?;
        }
    }

    visiting.remove(&entry_pc);
    Ok(())
}
