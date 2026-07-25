// src/analysis/transfer/call/mod.rs

pub mod callback;
pub mod checks;
pub mod compat;
pub mod helper_protos;
pub mod kfunc;
pub mod kfunc_protos;
pub mod mem_checks;
pub mod side_effects;
pub mod signatures;
pub mod transfer;
pub mod validators;

// Re-export public transfer functions
pub(crate) use kfunc::transfer_kfunc;
pub(crate) use transfer::transfer_call;
pub(crate) use transfer::transfer_call_rel;
