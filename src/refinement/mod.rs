//! Proof-guided abstraction refinement subsystem.
//!
//! Distinct from `crate::pcc` (whole-program proof-carrying code): this module
//! produces small per-site SMT proofs that refine the verifier's abstraction,
//! using BCF's binary format and cvc5 as the solver.
//!
//! Algorithmic reference: see the memory file
//! the BCF kernel patches (distilled from
//! set1 + set2 in `/Users/yalucai/BCF/patches-kernel/`).

pub mod bcf;
pub mod bundle;
pub mod emit;
pub mod canonical_hash;
pub mod refine_map;
pub mod refine_stack;
pub mod refine_unreachable;
pub mod smtlib;
pub mod solver;
pub mod symbolic;
