// src/analysis/transfer/call/validators/nullable.rs
//
// Unified handling for *OrNull argument types

use crate::analysis::machine::error::VerificationError;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;

use super::super::checks::ValidationContext;
use super::super::compat::{MAP_VALUE_OR_NULL_COMPAT, base_arg_type, is_compatible};
use super::super::mem_checks::validate_readable_mem;
use super::super::signatures::{ArgKind, get_nullable_ptr_size_pair};

/// Validates a nullable argument type (*OrNull variants).
/// If the register is provably NULL, validation passes.
/// Otherwise, validates against the base (non-null) type.
pub fn validate_nullable(ctx: &mut ValidationContext, expected: ArgKind) -> bool {
    let actual = ctx.actual;
    let types = ctx.types;

    // If provably zero (NULL), accept immediately
    if types.get(ctx.reg).is_scalar() && ctx.state.domain.proven_zero(ctx.reg) {
        return true;
    }

    // Route to type-specific nullable validation
    match expected {
        ArgKind::PtrToCtxOrNull => validate_ctx_or_null(ctx),
        ArgKind::PtrToStackOrNull => validate_stack_or_null(ctx),
        ArgKind::PtrToMemOrNull => validate_mem_or_null(ctx),
        ArgKind::PtrToMapValueOrNull => validate_map_value_or_null(ctx),
        _ => {
            // Fallback to base type validation
            let base = base_arg_type(expected);
            super::super::checks::validate_single_arg_inner(
                ctx.env,
                ctx.state,
                ctx.types,
                ctx.helper,
                ctx.pc,
                ctx.reg,
                base,
                actual,
                ctx.map_info,
                ctx.arg_index,
                ctx.mem_size_pairs,
            )
        }
    }
}

/// Validates PtrToCtxOrNull argument type.
fn validate_ctx_or_null(ctx: &mut ValidationContext) -> bool {
    let actual = ctx.actual;

    // If not provably zero, must be PtrToCtx
    if !matches!(actual, RegType::PtrToCtx) && !ctx.state.domain.proven_zero(ctx.reg) {
        ctx.fail_with_log(
            VerificationError::InvalidArgType {
                pc: ctx.pc,
                reg: ctx.reg,
            },
            &format!(
                "[Verifier] pc {}: R{} expected PTR_TO_CTX or NULL, got {:?}",
                ctx.pc,
                ctx.arg_index + 1,
                actual
            ),
        );
        return false;
    }
    true
}

/// Validates PtrToStackOrNull argument type.
fn validate_stack_or_null(ctx: &mut ValidationContext) -> bool {
    let actual = ctx.actual;

    if !matches!(actual, RegType::PtrToStack { .. }) && !ctx.state.domain.proven_zero(ctx.reg) {
        ctx.fail_with_log(
            VerificationError::InvalidArgType {
                pc: ctx.pc,
                reg: ctx.reg,
            },
            &format!(
                "[Verifier] pc {}: R{} expected PTR_TO_STACK or NULL, got {:?}",
                ctx.pc,
                ctx.arg_index + 1,
                actual
            ),
        );
        return false;
    }
    true
}

/// Validates PtrToMemOrNull argument type.
/// If nullable, also checks that paired size argument is zero.
fn validate_mem_or_null(ctx: &mut ValidationContext) -> bool {
    let reg_type = ctx.types.get(ctx.reg);

    if reg_type.is_nullable() {
        // Pointer is nullable - check that paired size arg is also 0
        if let Some(size_arg_idx) = get_nullable_ptr_size_pair(ctx.helper, ctx.arg_index) {
            let size_reg = [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5][size_arg_idx];
            if !ctx.state.domain.proven_zero(size_reg) {
                ctx.fail_with_log(
                    VerificationError::InvalidArgType {
                        pc: ctx.pc,
                        reg: size_reg,
                    },
                    &format!(
                        "[Verifier] pc {}: R{} must be 0 when R{} is NULL",
                        ctx.pc,
                        size_arg_idx + 1,
                        ctx.arg_index + 1
                    ),
                );
                return false;
            }
        }
        return validate_readable_mem(ctx.env, ctx.state, ctx.pc, ctx.reg, ctx.actual, None);
    }

    validate_readable_mem(ctx.env, ctx.state, ctx.pc, ctx.reg, ctx.actual, None)
}

/// Validates PtrToMapValueOrNull argument type.
fn validate_map_value_or_null(ctx: &mut ValidationContext) -> bool {
    let reg_type = ctx.types.get(ctx.reg);

    if !is_compatible(&reg_type, MAP_VALUE_OR_NULL_COMPAT) {
        ctx.fail_with_log(
            VerificationError::InvalidArgType {
                pc: ctx.pc,
                reg: ctx.reg,
            },
            &format!(
                "[Verifier] pc {}: R{} expected PTR_TO_MAP_VALUE or NULL, got {:?}",
                ctx.pc,
                ctx.arg_index + 1,
                ctx.actual
            ),
        );
        return false;
    }
    true
}
