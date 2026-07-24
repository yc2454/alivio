use crate::ast::Instr;
use crate::analysis::machine::reg::Reg;

/// A lightweight record of a single step in the execution path.
pub struct Breadcrumb {
    pub pc: usize,
    /// We format the instruction string eagerly so we don't hold references to the Program
    pub instr_str: String,
    /// The actual instruction at `pc` at the time of execution. Cloned so
    /// `mark_chain_precision_backward` can walk the history without
    /// re-borrowing `Program`. Cheap (Instr is a small enum); cost is
    /// outweighed by the simplification at the walk site.
    pub instr: Instr,
    /// The index of the previous step in the `History` vector
    pub parent_idx: Option<usize>,
    pub reg_types_str: String,
    /// Compact per-register interval snapshot at the time of execution.
    /// Formatted by `State::reg_ranges_str()`.
    pub reg_ranges_str: String,
    pub depth: usize,
    /// zovia's analog of the kernel's `INSN_F_STACK_ACCESS` jmp-history
    /// flag. Set during the forward transfer (back-patched onto the
    /// just-recorded breadcrumb) iff this insn performed a *register
    /// spill or fill* the kernel records `INSN_F_STACK_ACCESS` for:
    /// a slot-aligned scalar/const/ptr spill (`check_stack_write_fixed_off`)
    /// or a fill from a slot that `is_spilled_reg`
    /// (`check_stack_read_fixed_off`). `backtrack_insn_step` reads it to
    /// decide whether a stack LDX/STX continues the precision chain into
    /// the slot — exactly the kernel's `hist->flags & INSN_F_STACK_ACCESS`
    /// gate in `backtrack_insn`. A plain stack data write/read leaves it
    /// `false`, so the backtrack does not over-follow it (the previous
    /// `off % 8` structural guess followed every slot-aligned access,
    /// inflating the path-unreachable suffix and the non-prunable
    /// ancestor span).
    pub stack_access: bool,
    /// zovia's analog of the kernel's per-jmp-history `linked_regs`
    /// (verifier.c `push_insn_history(..., linked_regs_pack(...))` in
    /// `check_cond_jmp_op`). At a conditional jump, the set of scalar
    /// registers sharing the compared register's scalar id (kernel
    /// `collect_linked_regs`, recorded only when more than one reg is in
    /// the class). `bt_sync_linked_regs` in the backward precision walk
    /// reads it: if any member is precise, all become precise. Empty for
    /// non-conditional insns or a singleton class.
    pub linked_regs: Vec<Reg>,
}

pub struct History {
    steps: Vec<Breadcrumb>,
}

impl History {
    pub fn new() -> Self {
        Self {
            // Pre-allocate space to avoid frequent reallocations during analysis
            steps: Vec::with_capacity(10_000),
        }
    }

    /// Record a step and return its index (which acts as the ID).
    pub fn record(
        &mut self,
        pc: usize,
        instr: &Instr,
        reg_types_str: String,
        reg_ranges_str: String,
        depth: usize,
        parent_idx: Option<usize>,
    ) -> usize {
        let idx = self.steps.len();
        self.steps.push(Breadcrumb {
            pc,
            instr_str: format!("{:?}", instr),
            instr: *instr,
            reg_types_str,
            reg_ranges_str,
            depth,
            parent_idx,
            stack_access: false,
            linked_regs: Vec::new(),
        });
        idx
    }

    /// Back-patch the kernel-style `linked_regs` set onto an
    /// already-recorded breadcrumb. Called by the forward conditional-jump
    /// transfer once it has collected the id-linked scalar class (the
    /// kernel records this via `push_insn_history` in `check_cond_jmp_op`,
    /// only when the class has more than one member).
    pub fn set_linked_regs(&mut self, idx: usize, regs: Vec<Reg>) {
        if let Some(b) = self.steps.get_mut(idx) {
            b.linked_regs = regs;
        }
    }

    /// Back-patch the kernel-style `INSN_F_STACK_ACCESS` flag onto an
    /// already-recorded breadcrumb. Called by the forward stack
    /// store/load transfer once it has decided this insn is a real
    /// register spill/fill (the kernel sets the equivalent flag at the
    /// tail of `check_stack_{read,write}_fixed_off` via
    /// `push_jmp_history`, *after* the spill/fill classification).
    pub fn set_stack_access(&mut self, idx: usize) {
        if let Some(b) = self.steps.get_mut(idx) {
            b.stack_access = true;
        }
    }

    /// Walk backwards from the crash point to the start to reconstruct the trace.
    pub fn get_trace(&self, crash_idx: usize) -> Vec<&Breadcrumb> {
        let mut trace = Vec::new();
        let mut current = Some(crash_idx);

        while let Some(idx) = current {
            if let Some(step) = self.steps.get(idx) {
                trace.push(step);
                current = step.parent_idx;
            } else {
                break;
            }
        }

        // Reverse to get chronological order (Entry -> Crash)
        trace.reverse();
        trace
    }

    /// Collect all PCs visited on the path from `from_idx` back to (but not including)
    /// the first occurrence of `target_pc`. These are the PCs in the loop body.
    ///
    /// If `frame_depth` is Some, only collects PCs at that specific call depth.
    /// This filters out callee PCs when analyzing loops that contain BPF-to-BPF calls.
    pub fn loop_body_pcs(
        &self,
        from_idx: usize,
        target_pc: usize,
        frame_depth: Option<usize>,
    ) -> Vec<usize> {
        let mut pcs = Vec::new();
        let mut current = Some(from_idx);
        while let Some(idx) = current {
            if let Some(step) = self.steps.get(idx) {
                if step.pc == target_pc {
                    break;
                }
                // Only include PCs at the target frame depth (if specified)
                if frame_depth.is_none_or(|d| step.depth == d) {
                    pcs.push(step.pc);
                }
                current = step.parent_idx;
            } else {
                break;
            }
        }
        pcs
    }

    /// Check if `target_pc` was visited ANYWHERE on the path leading to `from_idx`.
    pub fn is_on_path(&self, from_idx: usize, target_pc: usize) -> bool {
        let mut current = Some(from_idx);
        while let Some(idx) = current {
            if let Some(step) = self.steps.get(idx) {
                if step.pc == target_pc {
                    return true;
                }
                current = step.parent_idx;
            } else {
                break;
            }
        }
        false
    }

    /// Check if `target_pc` was visited at the SAME stack depth on the path leading to `from_idx`.
    /// A PC is considered a back-edge only if the depth never dropped below current_depth.
    pub fn is_back_edge(&self, from_idx: usize, target_pc: usize, current_depth: usize) -> bool {
        let mut current = Some(from_idx);
        while let Some(idx) = current {
            if let Some(step) = self.steps.get(idx) {
                if step.depth < current_depth {
                    // We returned to a caller, so any PC further back is not a same-frame back-edge
                    return false;
                }
                if step.pc == target_pc && step.depth == current_depth {
                    return true;
                }
                current = step.parent_idx;
            } else {
                break;
            }
        }
        false
    }

    /// Get a step by index.
    pub fn get(&self, idx: usize) -> Option<&Breadcrumb> {
        self.steps.get(idx)
    }
}
