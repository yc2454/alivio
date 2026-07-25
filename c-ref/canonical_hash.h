/*
 * BCF canonical hash — C reference implementation.
 *
 * Specification: docs/userspace-bcf/canonical-hash-spec.md
 * Rust reference: src/refinement/canonical_hash.rs
 *
 * Property: for two BCF expressions a, b in their respective tables,
 *   bcf_checker.c::__expr_equiv(a, b, from_checker=false, own_args=false)
 *     == 1   ==>   alivio_canonical_hash(a) == alivio_canonical_hash(b)
 *
 * Must produce byte-for-byte identical output to the Rust impl on every
 * input. Cross-impl agreement is enforced by the integration test in
 * src/refinement/canonical_hash.rs (cross_impl_agrees).
 */

#ifndef ALIVIO_CANONICAL_HASH_H
#define ALIVIO_CANONICAL_HASH_H

#include <stdint.h>
#include <stddef.h>

/*
 * Mirrors src/refinement/bcf.rs::BcfExpr.
 *
 * `vlen` is the args length (matches the kernel's on-disk vlen field).
 * `args` points into a caller-owned buffer; the canonical-hash code does
 * not free it and does not mutate it.
 */
struct alivio_bcf_expr {
    uint8_t  code;
    uint8_t  vlen;
    uint16_t params;
    const uint32_t *args;
};

/*
 * Hash the expression rooted at `root` (an expr-id, i.e. an index into
 * `exprs`). `exprs_len` is the table length; used only for a sanity bound
 * check on args during the walk.
 *
 * Returns the 64-bit canonical hash.
 *
 * Recursion is bounded by the depth of the expression DAG when walked as a
 * tree. Callers handing in adversarial deeply-nested expressions should
 * impose a depth limit upstream.
 */
uint64_t alivio_canonical_hash(uint32_t root,
                              const struct alivio_bcf_expr *exprs,
                              size_t exprs_len);

#endif /* ALIVIO_CANONICAL_HASH_H */
