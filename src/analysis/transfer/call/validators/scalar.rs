// src/analysis/transfer/call/validators/scalar.rs
//
// Validators for scalar argument types: ConstSize, ConstSizeOrZero, ConstAllocSizeOrZero

use crate::analysis::machine::error::VerificationError;

use super::super::checks::ValidationContext;

/// Validates ConstSize argument type.
/// Value must be positive (> 0).
pub fn validate_const_size(ctx: &mut ValidationContext) -> bool {
    if !ctx.state.domain.proven_positive(ctx.reg) {
        ctx.fail_with_log(
            VerificationError::InvalidArgType {
                pc: ctx.pc,
                reg: ctx.reg,
            },
            &format!(
                "[Verifier] pc {}: R{} (ConstSize) must be positive",
                ctx.pc,
                ctx.arg_index + 1
            ),
        );
        return false;
    }
    mark_size_arg_precision_chain(ctx);
    true
}

/// Kernel `check_mem_size_reg` tail (verifier.c:8864) /
/// `ARG_CONST_ALLOC_SIZE_OR_ZERO` (verifier.c:10504): a helper SIZE
/// argument gets a full `mark_chain_precision(env, regno)` backward
/// walk on success — the size value determined a memory range, so its
/// lineage (including CACHED ancestor states) is precision-marked.
/// Range-checking the reg alone would leave the cached checkpoint's
/// size reg imprecise where the kernel has prec=1, so later arrivals
/// with a different size would wrongly HIT it.
/// The cur-state local mark is irrelevant (R0-R5 die at the call);
/// the cached-lineage marks are the load-bearing part.
fn mark_size_arg_precision_chain(ctx: &mut ValidationContext) {
    if let Some(hidx) = ctx.state.history_idx {
        crate::analysis::flow::precision::mark_chain_precision_backward(
            ctx.env,
            hidx,
            ctx.state.parent_cache_id,
            ctx.reg,
        );
    }
}

/// Validates ConstSizeOrZero or ConstAllocSizeOrZero argument type.
/// Value must be non-negative (>= 0).
pub fn validate_const_size_or_zero(ctx: &mut ValidationContext) -> bool {
    if !ctx.state.domain.proven_nonnegative(ctx.reg) {
        ctx.fail_with_log(
            VerificationError::InvalidArgType {
                pc: ctx.pc,
                reg: ctx.reg,
            },
            &format!(
                "[Verifier] pc {}: R{} (ConstSizeOrZero) must be non-negative",
                ctx.pc,
                ctx.arg_index + 1
            ),
        );
        return false;
    }
    mark_size_arg_precision_chain(ctx);
    true
}
