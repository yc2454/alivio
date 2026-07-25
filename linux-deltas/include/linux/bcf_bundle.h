/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_BCF_BUNDLE_H
#define _LINUX_BCF_BUNDLE_H

#include <linux/bpfptr.h>
#include <linux/types.h>
#include <uapi/linux/bcf.h>

struct bpf_verifier_env;

/*
 * Cap on bundle size to avoid runaway allocations from a malformed
 * BPF_PROG_LOAD. Typical bundles are < 1 MB. 64 MB is a generous ceiling.
 */
#define BCF_BUNDLE_MAX_SIZE (64u * 1024u * 1024u)

/*
 * Copy a userspace bundle into kernel memory, validate its structure,
 * and attach it to the verifier env. Releases ownership of the input
 * buffer if validation fails.
 *
 * Returns 0 on success; -errno on failure (-ENOMEM, -EFAULT, -EINVAL).
 */
int bcf_bundle_load(struct bpf_verifier_env *env, bpfptr_t ubuf, u32 size);

/*
 * Free any bundle attached to env. Safe to call when no bundle is
 * attached (no-op).
 */
void bcf_bundle_free(struct bpf_verifier_env *env);

/*
 * Look up the bundle entry whose cond_hash matches @cond_hash.
 * Returns NULL on miss or if no bundle is attached.
 *
 * Hash collisions are possible (64-bit fingerprint, see canonical-hash
 * spec); the caller MUST confirm structural equivalence via
 * __expr_equiv() before trusting the entry.
 */
const struct bcf_bundle_entry *bcf_bundle_lookup(struct bpf_verifier_env *env,
						  u64 cond_hash);

/* Accessors for an entry's payloads inside the bundle blob. */
static inline const void *
bcf_bundle_entry_goal(const void *bundle_blob,
		      const struct bcf_bundle_entry *e)
{
	return (const u8 *)bundle_blob + e->goal_off;
}

static inline const void *
bcf_bundle_entry_proof(const void *bundle_blob,
		       const struct bcf_bundle_entry *e)
{
	return (const u8 *)bundle_blob + e->proof_off;
}

#endif /* _LINUX_BCF_BUNDLE_H */
