// SPDX-License-Identifier: GPL-2.0-only
/*
 * BCF bundle parser + lookup.
 *
 * A "bundle" is a userspace-supplied blob containing pre-validated proofs
 * for refinement sites the verifier expects to encounter. Each entry is
 * keyed by the canonical hash of the goal expression; at refinement time
 * the kernel hashes its own kernel-side goal, looks up the entry, and
 * runs bcf_check_proof() inline. This replaces BCF's suspend/resume
 * round-trip with a single-pass load.
 *
 * Wire format: uapi/linux/bcf.h struct bcf_bundle_{header,entry}.
 * Spec: docs/userspace-bcf/canonical-hash-spec.md (userspace project).
 *
 * Threat model: bundles come from BPF_PROG_LOAD's `bcf_bundle` field.
 * The caller is whoever can already load BPF programs; we don't widen
 * privilege. Untrusted-input validation still applies because a confused
 * loader (or fuzzer) might supply a malformed bundle, and a kernel OOPS
 * on malformed input is unacceptable.
 */

#include <linux/bcf_bundle.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/bpfptr.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <uapi/linux/bcf.h>

/*
 * Validate a freshly-copied-in bundle blob. The blob is already in
 * kernel memory, size-bounded by the caller. Walks header + entries
 * checking magic, kinds, payload offset/size ranges, and alignment.
 *
 * Returns 0 if the structure checks out, -EINVAL otherwise.
 */
static int bcf_bundle_validate(const void *blob, u32 size)
{
	const struct bcf_bundle_header *hdr = blob;
	const struct bcf_bundle_entry *entries;
	u32 payload_start;
	u64 entries_end;
	u32 i;

	if (hdr->magic != BCF_BUNDLE_MAGIC)
		return -EINVAL;
	if (hdr->reserved != 0)
		return -EINVAL;
	if (hdr->total_size > size)
		return -EINVAL;

	entries_end = (u64)sizeof(*hdr) +
		      (u64)hdr->entry_cnt * sizeof(*entries);
	if (entries_end > hdr->total_size)
		return -EINVAL;

	payload_start = (u32)entries_end;
	entries = (const struct bcf_bundle_entry *)((const u8 *)blob +
						    sizeof(*hdr));

	for (i = 0; i < hdr->entry_cnt; i++) {
		const struct bcf_bundle_entry *e = &entries[i];
		u64 goal_end  = (u64)e->goal_off  + e->goal_size;
		u64 proof_end = (u64)e->proof_off + e->proof_size;

		if (e->kind != BCF_BUNDLE_KIND_REFINE &&
		    e->kind != BCF_BUNDLE_KIND_UNREACHABLE)
			return -EINVAL;

		if (e->goal_off < payload_start || goal_end > hdr->total_size)
			return -EINVAL;
		if (e->proof_off < payload_start || proof_end > hdr->total_size)
			return -EINVAL;

		/* Payloads must be u32-aligned (wire format invariant). */
		if ((e->goal_off & 3) || (e->proof_off & 3))
			return -EINVAL;
	}
	return 0;
}

int bcf_bundle_load(struct bpf_verifier_env *env, bpfptr_t ubuf, u32 size)
{
	void *blob;
	int err;

	if (size < sizeof(struct bcf_bundle_header))
		return -EINVAL;
	if (size > BCF_BUNDLE_MAX_SIZE)
		return -E2BIG;

	blob = kvmalloc(size, GFP_KERNEL);
	if (!blob)
		return -ENOMEM;

	if (copy_from_bpfptr(blob, ubuf, size)) {
		err = -EFAULT;
		goto err_free;
	}

	err = bcf_bundle_validate(blob, size);
	if (err)
		goto err_free;

	env->bcf.bundle_blob = blob;
	env->bcf.bundle_size = size;
	return 0;

err_free:
	kvfree(blob);
	return err;
}

void bcf_bundle_free(struct bpf_verifier_env *env)
{
	if (!env->bcf.bundle_blob)
		return;
	kvfree(env->bcf.bundle_blob);
	env->bcf.bundle_blob = NULL;
	env->bcf.bundle_size = 0;
}

const struct bcf_bundle_entry *
bcf_bundle_lookup(struct bpf_verifier_env *env, u64 cond_hash)
{
	const struct bcf_bundle_header *hdr;
	const struct bcf_bundle_entry *entries;
	u32 i;

	if (!env->bcf.bundle_blob)
		return NULL;

	hdr = env->bcf.bundle_blob;
	entries = (const struct bcf_bundle_entry *)((const u8 *)hdr +
						    sizeof(*hdr));

	/*
	 * Linear scan. Bundles in practice contain low hundreds of entries;
	 * a hashtable optimisation can come later if profiling shows this
	 * is hot. The trade-off is keeping the structure self-describing in
	 * the kernel without an extra build step.
	 */
	for (i = 0; i < hdr->entry_cnt; i++) {
		if (entries[i].cond_hash == cond_hash)
			return &entries[i];
	}
	return NULL;
}
