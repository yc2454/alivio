// src/analysis/machine/frame_stack.rs

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::{RegType, TypeState};
use crate::analysis::machine::stack_state::StackState;
use crate::domains::numeric::NumericDomain;
use crate::domains::tnum::Tnum;
use std::collections::HashMap;

/// A type-safe handle to a specific frame in the call stack.
/// Can only be created by FrameStack, preventing out-of-bounds access.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FrameLevel(usize);

impl FrameLevel {
    /// The main function frame (always valid).
    pub const MAIN: FrameLevel = FrameLevel(0);

    /// Create a FrameLevel from an index.
    /// Use with caution - only valid if index < num_frames.
    pub fn from_index(idx: usize) -> Self {
        FrameLevel(idx)
    }

    /// Index into the frame stack.
    pub fn index(self) -> usize {
        self.0
    }
}

impl std::fmt::Display for FrameLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "frame[{}]", self.0)
    }
}

/// Caller R6-R9 bcf reg-expr bindings, snapshotted at frame push.
///
/// Kernel analog: `bcf_expr` is a field of `struct bpf_reg_state`
/// (bpf_verifier.h:207) — per-reg, PER-FRAME. The callee frame's regs
/// are a separate array, so callee writes to r6-r9 never touch the
/// caller's bindings, and `prepare_func_exit` discards the callee frame
/// wholesale (only r0's reg state copies back, verifier.c:11708).
/// Alivio's `SymbolicState` reg table is flat across frames, so the
/// caller's bindings must be saved at push and restored at pop.
///
/// Always-equal on compare: the kernel's `states_equal`/`regsafe` never
/// reads `bcf_expr`, so the snapshot must not perturb the derived
/// `CallFrame` equality used by pruning.
#[derive(Clone, Debug, Default)]
pub struct BcfCalleeSavedRegSnap(pub Option<[(Option<u32>, Option<usize>); 4]>);

impl PartialEq for BcfCalleeSavedRegSnap {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for BcfCalleeSavedRegSnap {}

/// A saved call frame (caller's state when entering a subfunction).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallFrame {
    /// See [`BcfCalleeSavedRegSnap`]. `None` when the caller had no bcf.
    pub caller_bcf_reg_snap: BcfCalleeSavedRegSnap,
    pub return_pc: usize,
    pub stack: StackState,
    pub frame_depth: u16,

    // Caller's register state, captured at CallRel time.
    // Used to restore state on return and to compare caller
    // contexts during cross-frame pruning.
    pub caller_types: TypeState,
    pub caller_domain: NumericDomain,
    pub caller_tnums: HashMap<Reg, Tnum>,

    /// Innermost exception callback entry PC set on this frame.
    /// `bpf_throw` unwinds to the nearest enclosing frame with a handler;
    /// if none is set on any frame, the state's program-default handler
    /// is used (see [`State::program_exception_cb`]). Plumbing only in
    /// transfer semantics land. Read through
    /// [`CallFrame::exception_cb`] rather than touching the field.
    exception_cb: Option<usize>,

    /// True when this frame was entered through a callback-taking helper
    /// (`bpf_loop` / `bpf_for_each_map_elem` / `bpf_timer_set_callback`)
    /// rather than via a subprog CallRel. On Exit the callback
    /// path is dropped instead of merging back into the caller — the
    /// helper's post-call state is emitted separately at the call site.
    is_callback: bool,

    /// The helper id that entered this callback frame, when `is_callback`.
    /// Used on Exit to tighten the callback's return-value contract
    /// (e.g. bpf_loop requires R0 ∈ {0, 1}) —.
    callback_helper: Option<u32>,

    /// Snapshot of the caller frame's stack at cb-entry time. On clean
    /// cb-Exit we propagate the cb's writes to caller's stack onto the
    /// post-call skip-state (mirroring the kernel's iterative cb model
    /// in verifier.c v6.15 ~L10903 where cb iteration applies its own
    /// memory effects to the surviving post-call state). Comparing the
    /// post-cb stack against this snapshot tells us which slots cb
    /// touched, so we can widen only those when iteration count > 1.
    caller_stack_snapshot: Option<StackState>,

    /// Frame level of the caller at cb-push time. Identifies which
    /// frame's stack the cb might write through its ctx-arg pointer.
    caller_frame_level: Option<usize>,

    /// True when the cb may iterate ≥ 2 times so cb-touched slots must
    /// be widened on the post-call state. Mirrors the kernel's
    /// `widen_imprecise_scalars` pass after cb-return: only triggered
    /// when there's a "previous iteration" to compare against, which
    /// for nr_loops==1 (and find_vma which runs at most once) doesn't
    /// happen — those use concrete merge.
    cb_should_widen: bool,

    /// Set of caller-frame stack offsets that ANY branch of the cb body
    /// could write via the propagated ctx pointer. Pre-computed by a
    /// static scan of the cb subprog at frame-push time. On cb-Exit
    /// with `cb_should_widen` we invalidate all of these — not just
    /// the slots THIS cb-exit branch happened to write — so that the
    /// post-loop continuation reflects the kernel's multi-iteration
    /// cb model where different branches can fire on different
    /// iterations (e.g. `iter_limit_bug` where 2 iterations of a 3-
    /// branch cb can land on `{ctx.a=42, ctx.b=42, ctx.c=7}`).
    cb_writeable_caller_offsets: Vec<i16>,

    /// For global-subprog frames only: the caller's `rcu_read_depth` at
    /// call time. The kernel verifies global subprogs in isolation and
    /// treats their RCU lock-state changes as opaque to the caller —
    /// `bpf_rcu_read_unlock` inside a global subprog body must NOT
    /// decrement the caller's view of the depth. Restored on Exit by
    /// `transfer_exit` to mirror that opacity. `None` for static-subprog
    /// frames (which the kernel does inline so state changes propagate).
    /// Closes `rcu_read_lock.c::rcu_read_lock_global_subprog_unlock`.
    pub caller_rcu_read_depth_snapshot: Option<u32>,
}

impl Default for CallFrame {
    fn default() -> Self {
        CallFrame {
            caller_bcf_reg_snap: BcfCalleeSavedRegSnap(None),
            return_pc: 0,
            stack: StackState::default(),
            frame_depth: 0,
            caller_types: TypeState::default(),
            caller_domain: NumericDomain::default(),
            caller_tnums: HashMap::new(),
            exception_cb: None,
            is_callback: false,
            callback_helper: None,
            caller_stack_snapshot: None,
            caller_frame_level: None,
            cb_should_widen: false,
            cb_writeable_caller_offsets: Vec::new(),
            caller_rcu_read_depth_snapshot: None,
        }
    }
}

impl CallFrame {
    /// Exception callback registered on this frame, if any.
    pub fn exception_cb(&self) -> Option<usize> {
        self.exception_cb
    }

    /// True when this frame was entered through a callback-taking helper.
    pub fn is_callback(&self) -> bool {
        self.is_callback
    }

    /// Helper id that entered this callback frame, if `is_callback`.
    pub fn callback_helper(&self) -> Option<u32> {
        self.callback_helper
    }

    /// Caller frame's stack snapshot for cb-effect propagation, if set.
    pub fn caller_stack_snapshot(&self) -> Option<&StackState> {
        self.caller_stack_snapshot.as_ref()
    }

    /// Frame level of the caller at cb-push time.
    pub fn caller_frame_level(&self) -> Option<usize> {
        self.caller_frame_level
    }

    /// Whether cb-touched slots must be widened on post-call propagation.
    pub fn cb_should_widen(&self) -> bool {
        self.cb_should_widen
    }

    /// Set cb-effect propagation parameters at frame push time.
    pub fn set_cb_propagation(
        &mut self,
        caller_stack_snapshot: StackState,
        caller_frame_level: usize,
        should_widen: bool,
    ) {
        self.caller_stack_snapshot = Some(caller_stack_snapshot);
        self.caller_frame_level = Some(caller_frame_level);
        self.cb_should_widen = should_widen;
    }

    /// Pre-computed caller-frame offsets the cb body may write through
    /// its ctx pointer. Empty when no ctx-pointer arg or scan failed.
    pub fn cb_writeable_caller_offsets(&self) -> &[i16] {
        &self.cb_writeable_caller_offsets
    }

    /// Set the pre-computed cb-writeable caller offsets at frame push.
    pub fn set_cb_writeable_caller_offsets(&mut self, offsets: Vec<i16>) {
        self.cb_writeable_caller_offsets = offsets;
    }

    /// Register an exception callback entry PC on this frame. Overwrites
    /// any prior handler (matches kernel semantics: the most recent
    /// `bpf_set_exception_callback` wins).
    pub fn set_exception_cb(&mut self, pc: usize) {
        self.exception_cb = Some(pc);
    }

    /// Drop any exception callback on this frame.
    #[allow(dead_code)]
    pub fn clear_exception_cb(&mut self) {
        self.exception_cb = None;
    }
}

impl std::fmt::Display for CallFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CallFrame(return_pc={}, frame_depth={})",
            self.return_pc, self.frame_depth
        )
    }
}

/// A call stack that always has at least one frame (main).
///
/// The last element is always the "current" frame. Caller frames
/// sit below it. The main frame at index 0 can never be popped.
///
/// ```text
///   frames[0]       = main frame (always present)
///   frames[1]       = first callee frame (if in a subfunction)
///   ...
///   frames.last()   = current frame
/// ```
#[derive(Clone, Debug)]
pub struct FrameStack {
    // Invariant: never empty. frames[0] is always main.
    frames: Vec<CallFrame>,
}

impl FrameStack {
    /// Create a new frame stack with the main frame.
    pub fn new() -> Self {
        FrameStack {
            frames: vec![CallFrame::default()],
        }
    }

    // ── Current frame (most common operations) ──────────────────

    /// The level of the currently executing frame.
    pub fn current_level(&self) -> FrameLevel {
        FrameLevel(self.frames.len() - 1)
    }

    /// Immutable access to the current frame.
    pub fn current(&self) -> &CallFrame {
        // SAFETY: invariant guarantees non-empty
        self.frames.last().unwrap()
    }

    /// Mutable access to the current frame.
    pub fn current_mut(&mut self) -> &mut CallFrame {
        self.frames.last_mut().unwrap()
    }

    // ── Indexed access (for cross-frame spill/reload) ───────────

    /// Access a frame by level. Panics if level is invalid (bug in caller).
    pub fn get(&self, level: FrameLevel) -> &CallFrame {
        &self.frames[level.0]
    }

    /// Mutable access to a frame by level.
    pub fn get_mut(&mut self, level: FrameLevel) -> &mut CallFrame {
        &mut self.frames[level.0]
    }

    // ── Push / Pop ──────────────────────────────────────────────

    /// Enter a subfunction. Saves caller state into a new frame and pushes it.
    /// Returns the FrameLevel of the new (callee) frame.
    pub fn push(
        &mut self,
        return_pc: usize,
        caller_types: TypeState,
        caller_domain: NumericDomain,
        caller_tnums: HashMap<Reg, Tnum>,
    ) -> FrameLevel {
        self.push_inner(return_pc, caller_types, caller_domain, caller_tnums, None)
    }

    /// Push a callback frame. Same as [`push`] but flagged so
    /// Exit drops the path instead of merging into the caller; the
    /// originating helper id is stored for return-value tightening.
    pub fn push_callback(
        &mut self,
        return_pc: usize,
        caller_types: TypeState,
        caller_domain: NumericDomain,
        caller_tnums: HashMap<Reg, Tnum>,
        helper: u32,
    ) -> FrameLevel {
        self.push_inner(
            return_pc,
            caller_types,
            caller_domain,
            caller_tnums,
            Some(helper),
        )
    }

    fn push_inner(
        &mut self,
        return_pc: usize,
        caller_types: TypeState,
        caller_domain: NumericDomain,
        caller_tnums: HashMap<Reg, Tnum>,
        callback_helper: Option<u32>,
    ) -> FrameLevel {
        let frame = CallFrame {
            caller_bcf_reg_snap: BcfCalleeSavedRegSnap(None),
            return_pc,
            stack: StackState::default(),
            frame_depth: 0,
            caller_types,
            caller_domain,
            caller_tnums,
            exception_cb: None,
            is_callback: callback_helper.is_some(),
            callback_helper,
            caller_stack_snapshot: None,
            caller_frame_level: None,
            cb_should_widen: false,
            cb_writeable_caller_offsets: Vec::new(),
            caller_rcu_read_depth_snapshot: None,
        };
        self.frames.push(frame);
        self.current_level()
    }

    /// Return from a subfunction. Pops the current frame and returns
    /// it (owned) so the caller can restore register state.
    /// NOTE: We do NOT restore the caller frames' stacks. If the callee
    /// modified the caller's stack (via a passed pointer), those modifications
    /// persist. This matches kernel verifier behavior where stack state is
    /// not saved/restored on call/return.
    /// Returns None if already at main (nothing to pop).
    pub fn pop(&mut self) -> Option<CallFrame> {
        if self.frames.len() <= 1 {
            None
        } else {
            self.frames.pop()
        }
    }

    /// Whether we're in the main function (no active calls).
    pub fn at_main(&self) -> bool {
        self.frames.len() == 1
    }

    // ── Iteration (for pruning, subsumption checks) ─────────────

    /// Number of frames (always >= 1).
    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Iterate over all frames (main first, current last).
    pub fn iter(&self) -> impl Iterator<Item = &CallFrame> {
        self.frames.iter()
    }

    /// Total stack depth across all frames.
    pub fn total_stack_depth(&self) -> u16 {
        self.frames.iter().map(|f| f.frame_depth).sum()
    }

    /// Mutable iteration over all frames.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut CallFrame> {
        self.frames.iter_mut()
    }

    /// Invalidate all registers of a given type across all caller frames.
    /// Used when helpers like bpf_redirect invalidate packet pointers globally.
    pub fn invalidate_caller_reg_type(
        &mut self,
        should_invalidate: impl Fn(&RegType) -> bool,
        replacement: RegType,
    ) {
        for frame in self.frames.iter_mut() {
            for r in Reg::ALL {
                if should_invalidate(&frame.caller_types.get(r)) {
                    frame.caller_types.set(r, replacement);
                }
            }
        }
    }
}

impl Default for FrameStack {
    fn default() -> Self {
        Self::new()
    }
}
