/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * BCF bundle format — userspace-BCF UAPI (proposed).
 *
 * Authoritative spec: docs/userspace-bcf/canonical-hash-spec.md (canonical
 * hash); the bundle wire protocol is documented in this header.
 *
 * Frozen for step 3.3 of the Phase 3 plan. Step 3.4 will drop this verbatim
 * into the bpf-next worktree's `include/uapi/linux/bcf.h` alongside BCF's
 * existing expression / proof-rule definitions (which we reuse from the
 * upstream BCF series — see `/Users/yalucai/BCF/bcf-checker/include/uapi/linux/bcf.h`).
 *
 *
 * Wire layout (little-endian, all multi-byte fields u32-aligned):
 *
 *   +------------------------------------------------------------+
 *   |  struct bcf_bundle_header                                  |
 *   |    magic       u32   ('BCFB' little-endian = 0x42_46_43_42)|
 *   |    entry_cnt   u32                                         |
 *   |    total_size  u32   (bytes; whole bundle incl. header)    |
 *   |    reserved    u32   (must be 0; future flags/version)     |
 *   +------------------------------------------------------------+
 *   |  struct bcf_bundle_entry × entry_cnt                       |
 *   |    cond_hash   u64   (canonical_hash of goal_root)         |
 *   |    goal_off    u32   (byte offset from bundle start)       |
 *   |    goal_size   u32                                          |
 *   |    proof_off   u32                                          |
 *   |    proof_size  u32                                          |
 *   |    kind        u32                                          |
 *   +------------------------------------------------------------+
 *   |  goal-payload region and proof-payload region              |
 *   |  (interleaved or contiguous; addressed by per-entry        |
 *   |  offsets; each payload's offset is u32-aligned)            |
 *   +------------------------------------------------------------+
 *
 * Per-entry goal payload:
 *
 *   u32 root            (expr-id of the refinement-condition root within
 *                        this entry's local expression table)
 *   u32 expr_cnt
 *   expr_cnt × {
 *       u8  code        (operation | type; see linux/bcf.h)
 *       u8  vlen        (args length)
 *       u16 params
 *       u32 args[vlen]  (expr-ids for non-VAL nodes; raw value bytes for
 *                        BCF_BV|BCF_VAL constants — see expr_arg_is_id())
 *   }
 *
 * Per-entry proof payload:
 *
 *   Raw BCF proof bytes as produced by cvc5 / consumed by
 *   `bcf_check_proof()`. Contains its own header (struct bcf_proof_header)
 *   with BCF_MAGIC = 0x0BCF; the bundle does not duplicate that magic.
 *
 *
 * Lookup contract at a refinement site (kernel-side, step 3.4):
 *
 *   1. Build the kernel's refinement-condition expression `kg_root` in the
 *      verifier's own expression table.
 *   2. Compute h = bcf_canonical_hash(kg_root, kernel_exprs).
 *   3. Find the bundle entry with `entry.cond_hash == h`. (Linear scan or
 *      hashmap; choice deferred to 3.4.)
 *   4. Parse the entry's goal payload into a `struct bcf_expr` array.
 *   5. Confirm structural match: `__expr_equiv(kg_root_expr,
 *      bundle_goal_root_expr, from_checker=false, own_args=false) == 1`.
 *      If not, treat the hash hit as a collision and fall back to
 *      rejection (or continue searching, if multiple entries share a hash).
 *   6. Invoke `bcf_check_proof(bundle_goal_exprs, bundle_root,
 *      proof_payload, proof_size, ...)`. On status 0, accept the
 *      refinement site; otherwise reject.
 *
 * Hash collisions are harmless under this contract: every accept requires
 * a structural confirmation *and* a proof check. See canonical-hash-spec.md
 * §5–§6.
 */

#ifndef _UAPI__LINUX_BCF_BUNDLE_H__
#define _UAPI__LINUX_BCF_BUNDLE_H__

#include <linux/types.h>

#define BCF_BUNDLE_MAGIC 0x42464342u /* 'BCFB' little-endian */

/* Entry kinds. Refinement sites use BCF_BUNDLE_KIND_REFINE.
 * UNREACHABLE marks dead-path discharges. Reserved values are for future
 * proof-classes we have not enumerated.
 */
#define BCF_BUNDLE_KIND_REFINE      1u
#define BCF_BUNDLE_KIND_UNREACHABLE 2u

/**
 * struct bcf_bundle_header - first 16 bytes of every bundle blob.
 * @magic:      BCF_BUNDLE_MAGIC.
 * @entry_cnt:  Number of bcf_bundle_entry records that follow.
 * @total_size: Total bundle size in bytes, including this header.
 * @reserved:   Must be 0. Reserved for a future version/flags word.
 */
struct bcf_bundle_header {
	__u32 magic;
	__u32 entry_cnt;
	__u32 total_size;
	__u32 reserved;
};

/**
 * struct bcf_bundle_entry - one refinement entry.
 * @cond_hash:  Canonical hash of the refinement-condition root expression
 *              (see docs/userspace-bcf/canonical-hash-spec.md).
 * @goal_off:   Byte offset from the start of the bundle to this entry's
 *              goal payload. Must be u32-aligned.
 * @goal_size:  Goal-payload size in bytes.
 * @proof_off:  Byte offset to the BCF proof bytes (per bcf_proof_header).
 *              Must be u32-aligned.
 * @proof_size: Proof size in bytes.
 * @kind:       One of BCF_BUNDLE_KIND_*.
 *
 * Total size: 28 bytes.
 */
struct bcf_bundle_entry {
	__u64 cond_hash;
	__u32 goal_off;
	__u32 goal_size;
	__u32 proof_off;
	__u32 proof_size;
	__u32 kind;
} __attribute__((packed));

#endif /* _UAPI__LINUX_BCF_BUNDLE_H__ */
