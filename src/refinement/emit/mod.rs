// BCF emission — the interface the core verifier calls. Everything BCF
// that runs DURING verification lives under this module: path-cond
// recording at branches (`record`), the base->reject replay machinery
// (`replay`), and the reject-emission driver (`unreachable`). Core code
// interacts only through the re-exports below, always gated on
// `env.bcf_enabled` / `state.bcf`; with BCF off none of this executes.

pub mod map;
pub mod record;
pub mod replay;
pub mod unreachable;

pub(crate) use map::try_bcf_refine_map;
pub(crate) use record::{cmp_op_to_bcf_pair, record_path_cond_for_side};
pub(crate) use replay::replay_to_reject;
pub(crate) use unreachable::try_emit_path_unreachable_entry;

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;

/// Mirror the kernel's `bcf_refine` reg_masks=0 auto-fill for
/// `bcf_prove_unreachable` (verifier.c:24611-24620): every R0..R9 that
/// is not NOT_INIT and not a const non-scalar, then the backtrack
/// suffix base PC over that set. The kernel's `bcf_track` emits
/// br_conds only for that suffix; without this filter zovia's
/// path_cond goal carries spurious leading conditions (from its full
/// abstract-interpretation path) and its canonical hash misses the
/// kernel's bundle lookup. Shared by `unreachable_base_pc` (base/anchor)
/// AND the prev/cache-id computation so the two `bcf_suffix_base_pc*`
/// walks use an IDENTICAL mask — a drift empties the walks at different
/// insns and loses the base.
pub(crate) fn unreachable_target_regs(
    _env: &VerifierEnv,
    state: &State,
    hidx: Option<usize>,
) -> Vec<Reg> {
    use crate::analysis::machine::reg_types::RegType;
    const VARREGS: [Reg; 10] = [
        Reg::R0,
        Reg::R1,
        Reg::R2,
        Reg::R3,
        Reg::R4,
        Reg::R5,
        Reg::R6,
        Reg::R7,
        Reg::R8,
        Reg::R9,
    ];
    let mut targets: Vec<Reg> = Vec::new();
    for &r in &VARREGS {
        let ty = state.types.get(r);
        if matches!(ty, RegType::NotInit) {
            continue;
        }
        // Faithful port of the kernel's `bcf_refine` reg_masks==0 auto-fill
        // (verifier.c:24611-24620): skip a register that is
        // `type != SCALAR_VALUE && tnum_is_const(reg->var_off)`.
        //
        // zovia has no single per-register var_off tnum, but the interval
        // domain carries the faithful analog on `PtrOffset.var_off` (its doc:
        // "kernel tnum_range(reg->var_off)"): `tnum_is_const(var_off)` holds
        // iff the pointer's offset range is a single point (`min == max`), or
        // there is no `ptr_offset` at all (types that can't hold a variable
        // offset — they demote to scalar on `ptr += reg`, or track only a const
        // embedded offset). This is the SAME reliable analog the refine-target
        // selection uses (memory/map.rs); `var_off_contributor` is NOT reliable
        // (spill/fill doesn't always clear it).
        let var_off_const = state
            .domain
            .as_interval()
            .and_then(|iv| iv.get_ptr_offset(r))
            .is_none_or(|po| po.min_offset() == po.max_offset());
        if !matches!(ty, RegType::ScalarValue) && var_off_const {
            continue;
        }
        targets.push(r);
    }
    // The kernel auto-fill keeps ALL scalars — verifier.c:24610-18 has no
    // liveness/constraint check — so no dead-unknown post-filter here.
    let _ = hidx;
    targets
}

pub(crate) fn unreachable_base_pc(env: &VerifierEnv, state: &State) -> Option<usize> {
    // Start the backtrack at the *rejecting* insn's breadcrumb (kernel
    // `backtrack_states` `last_idx = cur->insn_idx` with skip_first), and
    // return the faithful `base->insn_idx` (parent_loc at bt-empty).
    let hidx = env.current_step_idx.or(state.history_idx)?;
    let targets = unreachable_target_regs(env, state, Some(hidx));
    let base = crate::analysis::flow::precision::bcf_suffix_base_pc(
        env,
        hidx,
        state.parent_cache_id,
        &targets,
    );
    if std::env::var("ZOVIA_DUMP_REGMASK").ok().as_deref() == Some("1") {
        let mut mask: u32 = 0;
        for &r in &targets {
            mask |= 1u32 << (r as u32);
        }
        eprintln!(
            "[regmask] reject_pc={} mask=0x{:x} targets={:?} base={:?}",
            state.pc, mask, targets, base
        );
    }
    base
}
