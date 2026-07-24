use crate::analysis::machine::error::VerificationError;
// src/analysis/transfer/memory/stack.rs

use super::access::AccessKind;
use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::frame_stack::FrameLevel;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::stack_state::StackState;
use crate::analysis::machine::state::State;
use crate::common::constants;
use crate::refinement::bundle::{RefineEntry, BCF_BUNDLE_KIND_REFINE};
use crate::refinement::refine_stack::try_refine_stack_oob;
use log::{error, info};

/// Wrap the stack-OOB refinement attempt with env-side bookkeeping. Returns
/// `true` if cvc5 discharged the OOB claim and the proof was stashed on
/// `env.bcf_proofs` for later bundle emit; otherwise `false` (caller should
/// proceed to the normal rejection path).
fn try_bcf_refine_stack(
    env: &mut VerifierEnv,
    state: &State,
    base: Reg,
    instruction_offset: i64,
    size: i64,
) -> bool {
    if state.bcf.is_none() {
        return false;
    }
    // Mirror kernel `bcf_refine_access_bound` (verifier.c:5393):
    // reg_masks = bit for `regno` when ptr is variable. For stack
    // refinements the size is always constant (instruction-encoded), so
    // no size-reg bit. Pass to the env-side `bcf_suffix_base_pc` walker
    // which mirrors `backtrack_states` and returns the kernel's base PC.
    // Also look up prev_insn_pc at the landed cache so the filter can
    // apply the kernel's record_path_cond-at-replay-start retention
    // (mirrors try_emit_path_unreachable_entry's wiring).
    let landed = state
        .history_idx
        .and_then(|hidx| crate::analysis::flow::precision::bcf_suffix_base_pc_and_cache_id(env, hidx, state.parent_cache_id, &[base]));
    let base_pc = landed.map(|(pc, _)| pc);
    let prev_insn_pc = landed.and_then(|(_, cid)| env.cached_prev_insn_pc(cid));
    let Some(ok) = try_refine_stack_oob(state, base, instruction_offset, size, base_pc, prev_insn_pc) else {
        return false;
    };
    let entry = RefineEntry::new(ok.goal_root, ok.sym.exprs, ok.proof_bytes, BCF_BUNDLE_KIND_REFINE);
    info!(
        target: "app",
        "[bcf] refined stack-OOB at base={:?} off={} size={}: cvc5 proof {} bytes (hash {:016x})",
        base, instruction_offset, size, entry.proof_bytes.len(), entry.cond_hash
    );
    // Dev hook: write each raw cvc5 proof to a sidecar `.bcf` file so it can
    // be scp'd to the Linux box and fed to `bcf-checker` directly without
    // unpacking the bundle. Set `ZOVIA_BCF_DUMP_PROOF=<path-prefix>`; each
    // proof writes to `<prefix>.<idx>.bcf` (idx is its position in the run).
    if let Ok(prefix) = std::env::var("ZOVIA_BCF_DUMP_PROOF") {
        let idx = env.bcf_proofs.len();
        let path = format!("{}.{}.bcf", prefix, idx);
        match std::fs::write(&path, &entry.proof_bytes) {
            Ok(_) => info!(target: "app", "[bcf] dumped raw proof to {}", path),
            Err(e) => log::warn!(target: "app", "[bcf] proof dump to {} failed: {}", path, e),
        }
    }
    if std::env::var("ZOVIA_BCF_CENSUS").ok().as_deref() == Some("1") {
        crate::refinement::emit::unreachable::census_log(
            "refine_stack", state.pc, -1, -1, entry.cond_hash,
            env.bcf_proofs.iter().any(|e| e.cond_hash == entry.cond_hash),
        );
    }
    env.bcf_proofs.push(entry);
    // Mirror kernel `bcf_refine` parent-marking (verifier.c:24904-24921);
    // see the matching block in `memory/map.rs::try_bcf_refine_map`.
    crate::analysis::flow::pruning::cache::mark_path_children_unsafe(env, state, landed.map(|(_, cid)| cid));
    true
}

/// Check if a stack access at (base + off) of size bytes is safe.
/// For reads, also checks that the memory is initialized.
pub fn check_stack_access(
    env: &mut VerifierEnv,
    state: &State,
    base: Reg,
    ptr_type_offset: Option<i64>,
    instruction_offset: i64,
    size: i64,
    pc: usize,
    kind: AccessKind,
    src_type_op: Option<RegType>,
    pointer_frame_lv: FrameLevel,
) {
    if state.current_frame_level() > pointer_frame_lv
        && matches!(kind, AccessKind::Write)
        && src_type_op.is_some()
        && let Some(ty) = src_type_op
        && matches!(ty, RegType::PtrToStack { .. })
    {
        env.fail(VerificationError::SpillToCaller { pc });
        return;
    }
    let current_frame_depth = -(state.total_stack_depth() as i64);
    let stack_being_accessed = state.stack_at(pointer_frame_lv);

    match ptr_type_offset {
        Some(base_off) => {
            let actual_offset = base_off + instruction_offset;
            let access_end = current_frame_depth + actual_offset + size;

            if !matches!(kind, AccessKind::HelperBuffer) && actual_offset % size != 0 {
                env.fail(VerificationError::MisalignedAccess {
                    pc,
                    off: actual_offset,
                });
                return;
            }

            if actual_offset < constants::BPF_STACK_MIN || access_end > constants::BPF_STACK_MAX {
                if try_bcf_refine_stack(env, state, base, instruction_offset, size) {
                    return; // refinement succeeded; this path is provably safe
                }
                error!(target: "app", "Stack access out of bounds at pc {}: off {} size {} (Known offset)", pc, actual_offset, size);
                env.fail(VerificationError::StackOutOfBounds {
                    pc,
                    off: actual_offset,
                    size,
                });
                return;
            }

            // Kernel `bpf_mark_stack_read` (verifier.c:3877 fills /
            // :8651 helper mem args): record the exact slots this READ
            // touches under the current callchain. Writes are marked at
            // the store transfer (full-slot gate).
            if !matches!(kind, AccessKind::Write) {
                let mask = crate::analysis::flow::live_stack::slot_mask(actual_offset, size);
                crate::analysis::flow::live_stack::mark_stack_read(
                    env,
                    state,
                    pointer_frame_lv.index(),
                    pc,
                    mask,
                );
            }
            check_stack_initialization(env, stack_being_accessed, kind, actual_offset, size, pc);
        }
        None => {
            let (lo, hi) = state.domain.get_distance_interval(base, Reg::R10);

            let safe = if lo != i64::MIN && hi != i64::MAX {
                let lower = lo;
                let upper = hi;
                let min_offset = lower + instruction_offset;
                let max_access_end = current_frame_depth + upper + instruction_offset + size;
                min_offset >= constants::BPF_STACK_MIN && max_access_end <= constants::BPF_STACK_MAX
            } else {
                false
            };

            if !safe {
                if try_bcf_refine_stack(env, state, base, instruction_offset, size) {
                    return; // refinement succeeded; this path is provably safe
                }
                error!(target: "app", "Stack access out of bounds at pc {}: off {} size {} (Unknown offset)", pc, instruction_offset, size);
                env.fail(VerificationError::StackOutOfBounds {
                    pc,
                    off: instruction_offset,
                    size,
                });
                return;
            }

            // Kernel variable-offset stack read (verifier.c:5868):
            // mark every slot the access might touch.
            if !matches!(kind, AccessKind::Write) && lo != i64::MIN && hi != i64::MAX {
                let span = (hi - lo) + size;
                let mask = crate::analysis::flow::live_stack::slot_mask(
                    lo + instruction_offset,
                    span,
                );
                crate::analysis::flow::live_stack::mark_stack_read(
                    env,
                    state,
                    pointer_frame_lv.index(),
                    pc,
                    mask,
                );
            }
            if lo != i64::MIN && hi != i64::MAX {
                for off_candidate in lo..=hi {
                    let actual_offset = off_candidate + instruction_offset;
                    check_stack_initialization(
                        env,
                        stack_being_accessed,
                        kind,
                        actual_offset,
                        size,
                        pc,
                    );
                }
            } else {
                env.fail(VerificationError::UninitializedStackRead { pc, offset: 0 });
            }
        }
    }
}

pub(crate) fn check_stack_initialization(
    env: &mut VerifierEnv,
    stack: &StackState,
    kind: AccessKind,
    actual_offset: i64,
    size: i64,
    pc: usize,
) {
    let allow_privileged_upper_half_read = |off: i64, sz: i64| -> bool {
        if !env.ctx.is_privileged() || sz != 4 {
            return false;
        }
        if off < i16::MIN as i64 || off > i16::MAX as i64 {
            return false;
        }
        let off = off as i16;
        if off.rem_euclid(8) != 4 {
            return false;
        }
        for i in 0..4 {
            if !stack.is_slot_initialized(off - 4 + i as i16) {
                return false;
            }
        }
        true
    };

    let allow_privileged_partial_u64_read = |off: i64, sz: i64| -> bool {
        if !env.ctx.is_privileged() || sz != 8 {
            return false;
        }
        if off < i16::MIN as i64 || off > i16::MAX as i64 {
            return false;
        }
        let off = off as i16;
        stack.is_slot_initialized(off)
    };

    match kind {
        AccessKind::Read => {
            // dynptr body bytes are opaque kernel metadata. A
            // direct read that overlaps any byte of an active dynptr's
            // 16-byte slot pair is the kernel's "invalid read from
            // stack" rejection. Programs reach inside via
            // `bpf_dynptr_read` / `bpf_dynptr_data` instead.
            if stack.read_overlaps_dynptr(actual_offset, size) {
                env.fail(VerificationError::InvalidStackRead {
                    pc,
                    offset: actual_offset,
                });
                return;
            }
            // same for open-coded iterators — body is opaque.
            if stack.access_overlaps_iterator(actual_offset, size) {
                env.fail(VerificationError::InvalidStackRead {
                    pc,
                    offset: actual_offset,
                });
                return;
            }

            let mut first_uninit: Option<i16> = None;
            for i in 0..size {
                let slot = (actual_offset + i) as i16;
                if !stack.is_slot_initialized(slot) {
                    first_uninit = Some(slot);
                    break;
                }
            }

            if first_uninit.is_some() {
                // Kernel allows uninit stack reads in privileged mode
                // (CAP_PERFMON / `env->allow_uninit_stack`). Slot is
                // uninit, so the downstream pointer-size check is
                // irrelevant — return early like the narrow allowances.
                if env.ctx.is_privileged()
                    || allow_privileged_upper_half_read(actual_offset, size)
                    || allow_privileged_partial_u64_read(actual_offset, size)
                {
                    return;
                }
                env.fail(VerificationError::UninitializedStackRead {
                    pc,
                    offset: actual_offset,
                });
                return;
            }

            for i in 0..size {
                let slot = (actual_offset + i) as i16;
                let slot_type = stack.get_slot_type(slot);
                if slot_type.is_pointer() && size != 8 {
                    error!(target: "app", "Pointer read with invalid size at pc {}: off {} size {}", pc, actual_offset, size);
                    env.fail(VerificationError::InvalidStackRead {
                        pc,
                        offset: actual_offset,
                    });
                }
            }
        }
        AccessKind::HelperBuffer | AccessKind::HelperPrimitive => {
            // same dynptr-body-read rule as direct loads —
            // helpers reading a stack region overlapping a dynptr's
            // opaque metadata bytes is rejected ("invalid read from
            // stack"). Catches `add_dynptr_to_map1` and friends.
            if stack.read_overlaps_dynptr(actual_offset, size) {
                env.fail(VerificationError::InvalidStackRead {
                    pc,
                    offset: actual_offset,
                });
                return;
            }
            // same for iter slots — helpers may not read or
            // write iter bodies. Catches probe_read_kernel(iter+7, 1).
            if stack.access_overlaps_iterator(actual_offset, size) {
                env.fail(VerificationError::InvalidStackRead {
                    pc,
                    offset: actual_offset,
                });
                return;
            }
            // Kernel verifier requires every byte of the helper buffer
            // range to be initialized for non-uninit pointer kinds (see
            // check_helper_mem_access). The previous `any_initialized`
            // gate let partially-initialized buffers slip through —
            // surfaced on the bpf_dynptr_from_mem(buf=R10-24,
            // size=16) test where bytes -16..-9 were uninit.
            //
            // Privileged-mode exception: `int_ptr.json::ARG_PTR_TO_LONG
            // half-uninitialized` exercises an 8-byte helper read where
            // only the lower 4 bytes are initialized. Kernel accepts in
            // privileged mode, rejects in unpriv (matches the same
            // exception already applied to direct reads above via
            // `allow_privileged_partial_u64_read`).
            let all_initialized =
                (0..size).all(|i| stack.is_slot_initialized((actual_offset + i) as i16));

            // Same priv-mode rule as direct reads: kernel
            // `env->allow_uninit_stack` lets helper buffer args skip the
            // initialization check entirely under CAP_PERFMON.
            if !all_initialized
                && !env.ctx.is_privileged()
                && !allow_privileged_partial_u64_read(actual_offset, size)
            {
                env.fail(VerificationError::UninitializedStackRead {
                    pc,
                    offset: actual_offset,
                });
            }
        }
        AccessKind::Write => {}
    }
}

pub fn check_stack_arg_readable(
    env: &mut VerifierEnv,
    state: &State,
    stack_offset: i64,
    size: i64,
    pc: usize,
    kind: AccessKind,
) {
    check_stack_access(
        env,
        state,
        Reg::R10,
        Some(stack_offset),
        0,
        size,
        pc,
        kind,
        None,
        state.current_frame_level(),
    )
}
