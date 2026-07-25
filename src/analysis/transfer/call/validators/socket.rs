// src/analysis/transfer/call/validators/socket.rs
//
// Validators for socket-related argument types: PtrToSocket, PtrToSockCommon, PtrToBTFIdSockCommon

use crate::analysis::machine::error::VerificationError;

use super::super::checks::ValidationContext;
use super::super::compat::{
    BTF_SOCK_COMMON_COMPAT, SOCK_COMMON_COMPAT, SOCKET_COMPAT, is_compatible,
};
use super::super::signatures::ArgKind;

/// Validates socket-related argument types.
/// Handles PtrToSocket, PtrToSockCommon, and PtrToBTFIdSockCommon.
pub fn validate_socket_arg(ctx: &mut ValidationContext, expected: ArgKind) -> bool {
    // bpf_sk_assign in an SK_LOOKUP program accepts a NULL sock (clears the
    // current selection) — the kernel proto for bpf_sk_lookup_assign is
    // ARG_PTR_TO_SOCKET | PTR_MAYBE_NULL. alivio maps it to BPF_SK_ASSIGN
    // with a non-null sock arg, so the standard `bpf_sk_assign(ctx, NULL, ...)`
    // pattern FALSE-REJECTed. Accept a proven-NULL scalar here, but ONLY for
    // SK_LOOKUP: the TC/sched-act bpf_sk_assign requires a non-NULL
    // ARG_PTR_TO_SOCK_COMMON, so accepting NULL unconditionally would be an
    // FA on a TC program (the kernel rejects TC bpf_sk_assign(skb, NULL)).
    if ctx.helper == crate::common::constants::BPF_SK_ASSIGN
        && ctx.arg_index == 1
        && matches!(ctx.env.ctx.prog_kind, crate::ast::ProgramKind::SkLookup)
        && ctx.actual.is_scalar()
        && ctx.state.domain.proven_zero(ctx.reg)
    {
        return true;
    }

    let actual = &ctx.actual;

    let (compat_table, type_name) = match expected {
        ArgKind::PtrToSocket => (SOCKET_COMPAT, "PTR_TO_SOCKET"),
        ArgKind::PtrToSockCommon => (SOCK_COMMON_COMPAT, "PTR_TO_SOCK_COMMON"),
        ArgKind::PtrToBTFIdSockCommon => (BTF_SOCK_COMMON_COMPAT, "PTR_TO_BTF_ID_SOCK_COMMON"),
        _ => {
            // Should not happen if called correctly
            return true;
        }
    };

    if !is_compatible(actual, compat_table) {
        ctx.fail_with_log(
            VerificationError::InvalidArgType {
                pc: ctx.pc,
                reg: ctx.reg,
            },
            &format!(
                "[Verifier] pc {}: R{} expected {}, got {:?}",
                ctx.pc,
                ctx.arg_index + 1,
                type_name,
                actual
            ),
        );
        return false;
    }

    true
}
