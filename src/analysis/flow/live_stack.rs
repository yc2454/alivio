// src/analysis/flow/live_stack.rs
//
// Live stack slots analysis — mirror of kernel/bpf/liveness.c (bpf-next
// fee204688). Call-chain-sensitive, slot-granular (8-byte spi) READ/WRITE
// mark accumulation during exploration + backward-dataflow propagation,
// consumed by `clean_verifier_state` to decide which stack slots matter
// when comparing a cur state against a cached one.
//
// Why this replaces the static `live_slots` for slot cleaning: zovia's
// static per-byte stack liveness cannot see stack bytes read by a HELPER
// through a pointer argument (e.g. `r2 = r10-24; call map_lookup_elem` —
// the key bytes). Those slots look dead → `stack_subsumed_by`'s
// dead-slot skip would merge states the kernel keeps distinct on
// per-byte slot kinds. The kernel's answer is DYNAMIC read marks
// recorded with exact byte ranges at access-check time; this module is
// that mechanism.
//
// Kernel structure mapping:
//   bpf_liveness / func_instance     -> LiveStack / FuncInstance
//   compute_callchain                -> callchain_of (Vec of callsites,
//                                       frames 1..=curframe; [] = main)
//   bpf_mark_stack_read              -> mark_stack_read
//   bpf_reset_stack_write_marks      -> reset_stack_write_marks
//   bpf_mark_stack_write             -> mark_stack_write
//   bpf_commit_stack_write_marks     -> commit_stack_write_marks
//   bpf_reset_live_stack_callchain   -> invalidate_write_bracket (called
//                                       at frame push/pop so a CallRel /
//                                       Exit insn never commits an empty
//                                       must_write at the callsite — the
//                                       kernel gets this via cur_instance
//                                       being NULLed)
//   bpf_update_live_stack            -> update_live_stack (at every path
//                                       death + subprog exit)
//   bpf_stack_slot_alive             -> slot_alive / frame_alive_mask
//   env->bcf.tracking gates          -> env.replay_mode gates
//
// Differences from the kernel, all mechanical:
//   - instruction successors + per-subprog postorder are precomputed at
//     init() from the AST (kernel uses env->cfg.insn_postorder);
//   - instances are keyed by the callsite vector in a HashMap (kernel:
//     jhash table); missing instance on query = "no marks" = dead, the
//     same result the kernel gets from a NULL frame array;
//   - `bpf_calls_callback` at an outer callsite is over-approximated by
//     testing liveness at BOTH callsite and callsite+1 (union = more
//     alive = sound direction).

use std::collections::HashMap;

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::state::State;
use crate::ast::{Instr, Program};

pub const MAX_FRAMES: usize = 8;

/// Kernel `struct per_frame_masks`.
#[derive(Clone, Copy, Default)]
struct PerFrameMasks {
    may_read: u64,
    must_write: u64,
    must_write_acc: u64,
    live_before: u64,
}

/// Kernel `struct func_instance`: marks for one (callchain) over the
/// innermost function's instructions.
struct FuncInstance {
    /// Subprog bounds of the innermost function of this callchain.
    start: usize,
    end: usize,
    /// curframe + 1.
    nframes: usize,
    /// Per frame, per (insn - start) masks; frames allocated lazily.
    frames: Vec<Option<Vec<PerFrameMasks>>>,
    /// Per (insn - start): has must_write been committed at least once?
    must_write_set: Vec<bool>,
    updated: bool,
    must_write_dropped: bool,
}

impl FuncInstance {
    fn new(start: usize, end: usize, nframes: usize) -> Self {
        FuncInstance {
            start,
            end,
            nframes,
            frames: vec![None; nframes],
            must_write_set: vec![false; end - start],
            updated: false,
            must_write_dropped: false,
        }
    }

    fn masks(&self, frame: usize, insn: usize) -> Option<&PerFrameMasks> {
        if insn < self.start || insn >= self.end {
            return None;
        }
        self.frames
            .get(frame)?
            .as_ref()
            .map(|v| &v[insn - self.start])
    }

    fn alloc_masks(&mut self, frame: usize, insn: usize) -> Option<&mut PerFrameMasks> {
        if insn < self.start || insn >= self.end || frame >= self.nframes {
            return None;
        }
        let len = self.end - self.start;
        let slot = &mut self.frames[frame];
        if slot.is_none() {
            *slot = Some(vec![PerFrameMasks::default(); len]);
        }
        slot.as_mut().map(|v| &mut v[insn - self.start])
    }
}

/// Kernel `struct bpf_liveness` + the precomputed CFG data it reads from
/// `env->cfg` / `env->subprog_info`.
#[derive(Default)]
pub struct LiveStack {
    instances: HashMap<Vec<usize>, FuncInstance>,
    /// Sorted (start, end) subprog ranges.
    subprogs: Vec<(usize, usize)>,
    /// Per-insn successor lists (kernel `bpf_insn_successors`).
    successors: Vec<Vec<usize>>,
    /// Per subprog start: postorder list of reachable insns.
    postorder: HashMap<usize, Vec<usize>>,
    /// Write-mark accumulation bracket (kernel write_masks_acc /
    /// write_insn_idx + the implicit cur_instance identity).
    write_acc: [u64; MAX_FRAMES],
    write_insn: usize,
    write_key: Option<Vec<usize>>,
    enabled: bool,
}

/// spi for a (negative) stack byte offset. Kernel: `slot = -off - 1;
/// spi = slot / BPF_REG_SIZE`.
pub fn spi_of(off: i64) -> Option<u32> {
    if off >= 0 || off < -512 {
        return None;
    }
    Some(((-off - 1) / 8) as u32)
}

/// Slot mask covering bytes [off, off+size).
pub fn slot_mask(off: i64, size: i64) -> u64 {
    let mut mask = 0u64;
    let mut b = off;
    while b < off + size {
        if let Some(spi) = spi_of(b) {
            mask |= 1u64 << spi;
        }
        b += 1;
    }
    mask
}

/// Kernel `compute_callchain`: callsite insn indexes for frames
/// 1..=curframe (outer to inner). Empty for a main-frame-only state.
pub fn callchain_of(state: &State) -> Vec<usize> {
    use crate::analysis::machine::frame_stack::FrameLevel;
    let depth = state.frames.depth();
    (1..depth)
        .map(|i| {
            state
                .frames
                .get(FrameLevel::from_index(i))
                .return_pc
                .saturating_sub(1)
        })
        .collect()
}

fn subprog_of(subprogs: &[(usize, usize)], pc: usize) -> Option<(usize, usize)> {
    subprogs
        .iter()
        .find(|&&(s, e)| pc >= s && pc < e)
        .copied()
}

/// Build the module's CFG data. Called once per analyzed function, next
/// to `compute_liveness`.
pub fn init(env: &mut VerifierEnv, prog: &Program) {
    let n = prog.instrs.len();
    let mut successors: Vec<Vec<usize>> = Vec::with_capacity(n);
    for (pc, instr) in prog.instrs.iter().enumerate() {
        // Kernel `bpf_insn_successors` opcode table: EXIT none; JA jump
        // only; conditional jumps + JCOND both; everything else (incl.
        // helper calls and pseudo calls) falls through. ldimm64 occupies
        // two pcs — fall through skips the invalid second half.
        let next = if prog.invalid_pc_set.contains(&(pc + 1)) {
            pc + 2
        } else {
            pc + 1
        };
        let mut succ = Vec::new();
        match instr {
            Instr::Exit => {}
            Instr::Jmp { target } => succ.push(*target),
            Instr::If { target, .. } | Instr::MayGoto { target } => {
                if next < n {
                    succ.push(next);
                }
                succ.push(*target);
            }
            _ => {
                if next < n {
                    succ.push(next);
                }
            }
        }
        succ.retain(|&t| t < n);
        successors.push(succ);
    }

    let sp = crate::analysis::flow::subprog::analyze_subprograms(&prog.instrs);
    let subprogs: Vec<(usize, usize)> = sp.values().map(|i| (i.start_pc, i.end_pc)).collect();

    // Per-subprog postorder over reachable insns (kernel
    // env->cfg.insn_postorder, subprog-sliced).
    let mut postorder: HashMap<usize, Vec<usize>> = HashMap::new();
    for &(start, end) in &subprogs {
        let mut order = Vec::new();
        let mut seen = vec![false; end - start];
        // Iterative DFS with explicit post-visit.
        let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
        if start < end {
            seen[0] = true;
        }
        while let Some(&mut (pc, ref mut si)) = stack.last_mut() {
            let succ = &successors[pc];
            let mut advanced = false;
            while *si < succ.len() {
                let t = succ[*si];
                *si += 1;
                if t >= start && t < end && !seen[t - start] {
                    seen[t - start] = true;
                    stack.push((t, 0));
                    advanced = true;
                    break;
                }
            }
            if !advanced {
                order.push(pc);
                stack.pop();
            }
        }
        postorder.insert(start, order);
    }

    env.live_stack = LiveStack {
        instances: HashMap::new(),
        subprogs,
        successors,
        postorder,
        write_acc: [0; MAX_FRAMES],
        write_insn: 0,
        write_key: None,
        enabled: true,
    };
}

fn get_or_create<'a>(
    ls: &'a mut LiveStack,
    key: &[usize],
    pc_in_func: usize,
) -> Option<&'a mut FuncInstance> {
    if !ls.instances.contains_key(key) {
        let (start, end) = subprog_of(&ls.subprogs, pc_in_func)?;
        ls.instances
            .insert(key.to_vec(), FuncInstance::new(start, end, key.len() + 1));
    }
    ls.instances.get_mut(key)
}

/// Kernel `bpf_mark_stack_read`: accumulate may_read for @frameno at
/// @insn_idx under @state's callchain.
pub fn mark_stack_read(
    env: &mut VerifierEnv,
    state: &State,
    frameno: usize,
    insn_idx: usize,
    mask: u64,
) {
    // Diagnostic (ZOVIA_DBG_SPI=N): report every read-mark CALL on a
    // frame0 slot — including gated-out ones (replay/disabled).
    if frameno == 0
        && let Ok(spi_s) = std::env::var("ZOVIA_DBG_SPI")
        && let Ok(spi) = spi_s.parse::<u32>()
        && mask & (1u64 << spi) != 0
    {
        eprintln!(
            "[dbg-spi] frame0 spi={} read-mark call insn={} mask=0x{:x} enabled={} replay={}",
            spi, insn_idx, mask, env.live_stack.enabled, env.replay_mode
        );
    }
    if !env.live_stack.enabled || env.replay_mode || mask == 0 {
        return;
    }
    let key = callchain_of(state);
    let ls = &mut env.live_stack;
    let Some(inst) = get_or_create(ls, &key, insn_idx) else {
        return;
    };
    let live_before = inst.masks(frameno, insn_idx).map(|m| m.live_before).unwrap_or(0);
    let Some(m) = inst.alloc_masks(frameno, insn_idx) else {
        return;
    };
    let new_may_read = m.may_read | mask;
    if new_may_read != m.may_read && (new_may_read | live_before) != live_before {
        inst.updated = true;
    }
    let Some(m) = inst.alloc_masks(frameno, insn_idx) else {
        return;
    };
    m.may_read |= mask;
}

/// Kernel `bpf_reset_stack_write_marks`: open the per-insn write bracket.
pub fn reset_stack_write_marks(env: &mut VerifierEnv, state: &State, insn_idx: usize) {
    if !env.live_stack.enabled || env.replay_mode {
        return;
    }
    let key = callchain_of(state);
    let ls = &mut env.live_stack;
    ls.write_key = Some(key);
    ls.write_insn = insn_idx;
    ls.write_acc = [0; MAX_FRAMES];
}

/// Kernel `bpf_mark_stack_write`: accumulate a write mask for @frameno.
pub fn mark_stack_write(env: &mut VerifierEnv, frameno: usize, mask: u64) {
    if !env.live_stack.enabled || env.replay_mode {
        return;
    }
    let ls = &mut env.live_stack;
    if ls.write_key.is_some() && frameno < MAX_FRAMES {
        ls.write_acc[frameno] |= mask;
    }
}

/// Kernel `bpf_reset_live_stack_callchain`: a frame push/pop happened
/// mid-insn — the open bracket no longer matches the state's callchain,
/// so the commit for this insn must not happen (the kernel gets this by
/// NULLing cur_instance; commit on NULL is a no-op).
pub fn invalidate_write_bracket(env: &mut VerifierEnv) {
    env.live_stack.write_key = None;
}

/// Kernel `bpf_commit_stack_write_marks`: intersect the bracketed write
/// masks into must_write at the bracket's insn.
pub fn commit_stack_write_marks(env: &mut VerifierEnv) {
    if std::env::var("ZOVIA_DBG_WCOMMIT").ok().as_deref() == Some("1")
        && env.live_stack.write_insn == 1433
        && env.live_stack.write_key.is_some()
    {
        eprintln!(
            "[dbg-wcommit-entry] insn=1433 enabled={} replay={} acc0=0x{:x}",
            env.live_stack.enabled, env.replay_mode, env.live_stack.write_acc[0]
        );
    }
    if !env.live_stack.enabled || env.replay_mode {
        return;
    }
    let ls = &mut env.live_stack;
    let Some(key) = ls.write_key.take() else {
        return;
    };
    let write_insn = ls.write_insn;
    let acc = ls.write_acc;
    let Some(inst) = get_or_create(ls, &key, write_insn) else {
        return;
    };
    if write_insn < inst.start || write_insn >= inst.end {
        return;
    }
    let idx = write_insn - inst.start;
    let was_set = inst.must_write_set[idx];
    if std::env::var("ZOVIA_DBG_WCOMMIT").ok().as_deref() == Some("1") && write_insn == 1433 {
        eprintln!(
            "[dbg-wcommit] insn=1433 was_set={} acc0=0x{:x}",
            was_set, acc[0]
        );
    }
    for frame in 0..inst.nframes.min(MAX_FRAMES) {
        let mut mask = acc[frame];
        // avoid allocating frames for zero masks
        if mask == 0 && !was_set {
            continue;
        }
        let Some(m) = inst.alloc_masks(frame, write_insn) else {
            continue;
        };
        let old = m.must_write;
        if was_set {
            mask &= old;
        }
        if old != mask {
            m.must_write = mask;
            inst.updated = true;
        }
        if old & !mask != 0 {
            inst.must_write_dropped = true;
        }
    }
    inst.must_write_set[idx] = true;
}

/// Kernel `update_insn`: one dataflow step for (instance, frame, insn).
fn update_insn(
    inst: &mut FuncInstance,
    successors: &[Vec<usize>],
    frame: usize,
    insn: usize,
) -> bool {
    let succ = &successors[insn];
    if succ.is_empty() {
        return false;
    }
    let mut new_after = 0u64;
    let mut must_write_acc = u64::MAX;
    for &s in succ {
        let (lb, mwa) = inst
            .masks(frame, s)
            .map(|m| (m.live_before, m.must_write_acc))
            .unwrap_or((0, 0));
        new_after |= lb;
        must_write_acc &= mwa;
    }
    let Some(m) = inst.alloc_masks(frame, insn) else {
        return false;
    };
    must_write_acc |= m.must_write;
    let new_before = (new_after & !m.must_write) | m.may_read;
    let changed = new_before != m.live_before || must_write_acc != m.must_write_acc;
    m.live_before = new_before;
    m.must_write_acc = must_write_acc;
    changed
}

/// Kernel `update_instance`: fixed point over the subprog's postorder,
/// then transfer marks to the caller's instance.
fn update_instance(env: &mut VerifierEnv, key: &[usize]) {
    // Take the instance out to sidestep aliasing with ls.successors.
    let Some(mut inst) = env.live_stack.instances.remove(key) else {
        return;
    };
    if inst.must_write_dropped {
        for frame in 0..inst.nframes {
            if let Some(arr) = inst.frames[frame].as_mut() {
                for m in arr.iter_mut() {
                    m.must_write_acc = 0;
                }
            }
        }
    }
    let po = env
        .live_stack
        .postorder
        .get(&inst.start)
        .cloned()
        .unwrap_or_default();
    let successors = std::mem::take(&mut env.live_stack.successors);
    loop {
        let mut changed = false;
        for frame in 0..inst.nframes {
            if inst.frames[frame].is_none() {
                continue;
            }
            for &i in &po {
                changed |= update_insn(&mut inst, &successors, frame, i);
            }
        }
        if !changed {
            break;
        }
    }
    env.live_stack.successors = successors;

    // Kernel `propagate_to_outer_instance`.
    if !key.is_empty() {
        let callsite = key[key.len() - 1];
        let outer_key = &key[..key.len() - 1];
        let this_start = inst.start;
        // (must_write_acc, live_before) at subprog entry, per outer frame.
        let entry: Vec<(usize, u64, u64)> = (0..inst.nframes - 1)
            .filter_map(|frame| {
                inst.masks(frame, this_start)
                    .map(|m| (frame, m.must_write_acc, m.live_before))
            })
            .collect();
        let ls = &mut env.live_stack;
        if let Some(outer) = get_or_create(ls, outer_key, callsite)
            && callsite >= outer.start
            && callsite < outer.end
        {
            let idx = callsite - outer.start;
            let was_set = outer.must_write_set[idx];
            for &(frame, mwa, lb) in &entry {
                // must_write at the callsite: commit-style intersection.
                let mut mask = mwa;
                let mut set_updated = false;
                let mut set_dropped = false;
                if mask != 0 || was_set {
                    if let Some(m) = outer.alloc_masks(frame, callsite) {
                        let old = m.must_write;
                        if was_set {
                            mask &= old;
                        }
                        if old != mask {
                            m.must_write = mask;
                            set_updated = true;
                        }
                        if old & !mask != 0 {
                            set_dropped = true;
                        }
                    }
                }
                // may_read at the callsite.
                if lb != 0 {
                    let live_before = outer
                        .masks(frame, callsite)
                        .map(|m| m.live_before)
                        .unwrap_or(0);
                    if let Some(m) = outer.alloc_masks(frame, callsite) {
                        let new_may_read = m.may_read | lb;
                        if new_may_read != m.may_read
                            && (new_may_read | live_before) != live_before
                        {
                            set_updated = true;
                        }
                        m.may_read |= lb;
                    }
                }
                if set_updated {
                    outer.updated = true;
                }
                if set_dropped {
                    outer.must_write_dropped = true;
                }
            }
            outer.must_write_set[idx] = true;
        }
    }

    inst.updated = false;
    inst.must_write_dropped = false;
    env.live_stack.instances.insert(key.to_vec(), inst);
}

/// Kernel `bpf_update_live_stack`: propagate marks for every callchain
/// prefix of @key, innermost first. Call at every path death and at
/// subprog exit (with the pre-pop callchain).
pub fn update_live_stack(env: &mut VerifierEnv, key: &[usize]) {
    if !env.live_stack.enabled || env.replay_mode {
        return;
    }
    for l in (0..=key.len()).rev() {
        let k = &key[..l];
        let needs = env
            .live_stack
            .instances
            .get(k)
            .map(|i| i.updated)
            .unwrap_or(false);
        if needs {
            update_instance(env, k);
        }
    }
}

fn is_live_before(inst: &FuncInstance, insn: usize, frameno: usize, spi: u32) -> bool {
    inst.masks(frameno, insn)
        .map(|m| m.live_before & (1u64 << spi) != 0)
        .unwrap_or(false)
}

/// Kernel `bpf_stack_slot_alive` batched over all 64 spis: alive mask
/// for @frameno of a visited state at @q_insn with callchain @key.
pub fn frame_alive_mask(ls: &LiveStack, key: &[usize], q_insn: usize, frameno: usize) -> u64 {
    if !ls.enabled {
        return u64::MAX;
    }
    let curframe = key.len();
    let mut alive = 0u64;
    if let Some(inst) = ls.instances.get(key) {
        for spi in 0..64 {
            if is_live_before(inst, q_insn, frameno, spi) {
                alive |= 1u64 << spi;
            }
        }
    }
    // Outer frames: alive after the callsite (kernel checks callsite
    // for callback-calling sites, callsite+1 otherwise; we take the
    // union — over-approximating alive is the sound direction).
    for i in frameno..curframe {
        let callsite = key[i];
        if let Some(inst) = ls.instances.get(&key[..i]) {
            for spi in 0..64 {
                if alive & (1u64 << spi) != 0 {
                    continue;
                }
                if is_live_before(inst, callsite, frameno, spi)
                    || is_live_before(inst, callsite + 1, frameno, spi)
                {
                    alive |= 1u64 << spi;
                }
            }
        }
    }
    alive
}

/// Throwaway diagnostic (ZOVIA_DBG_LIVE26): dump one spi's per-insn
/// dataflow bits for the given instance at the given insns.
pub fn dbg_dump_bit(ls: &LiveStack, key: &[usize], frameno: usize, spi: u32, insns: &[usize]) {
    let Some(inst) = ls.instances.get(key) else {
        eprintln!("[dbg-live] no instance for key {:?}", key);
        return;
    };
    for &i in insns {
        match inst.masks(frameno, i) {
            Some(m) => eprintln!(
                "[dbg-live] insn={} spi={} may_read={} must_write={} live_before={}",
                i, spi,
                (m.may_read >> spi) & 1,
                (m.must_write >> spi) & 1,
                (m.live_before >> spi) & 1
            ),
            None => eprintln!("[dbg-live] insn={} spi={} NO MASKS", i, spi),
        }
    }
}
