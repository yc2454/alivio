// SPDX-License-Identifier: GPL-2.0-only
/*
 * BCF canonical hash — kernel implementation.
 *
 * Spec: docs/userspace-bcf/canonical-hash-spec.md
 * Userspace reference: c-ref/canonical_hash.c
 *
 * Computes a 64-bit fingerprint of a BCF expression rooted at `root` over
 * an expression table, such that two expressions equivalent under
 * `__expr_equiv(a, b, from_checker=false, own_args=false)` produce the
 * same fingerprint. Used at refinement sites to look up a bundle entry
 * whose proof discharges the same goal.
 *
 * Mirrors the userspace impl byte-for-byte. Both impls walk the
 * expression as a tree in post-order, emit a tagged record per node into
 * a buffer, then SipHash-2-4 that buffer with an all-zero key.
 *
 * Kernel-specific deviations from the userspace ref:
 *  - Recursion → explicit stack (kernel stacks are tight; ~64 levels deep
 *    is plenty for any expression we expect; -E2BIG above that).
 *  - SipHash via <linux/siphash.h> (same algorithm, same output).
 *  - Allocations are GFP_KERNEL kmalloc; cleaned up on every return path.
 *  - Returns -errno on failure via the out_hash out-parameter idiom.
 */

#include <linux/bcf_checker.h>
#include <linux/slab.h>
#include <linux/siphash.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <uapi/linux/bcf.h>

/* Record tags. See spec §3.1. */
#define BCF_HASH_TAG_VAR        0x01
#define BCF_HASH_TAG_LEAF_CONST 0x02
#define BCF_HASH_TAG_INTERNAL   0x03

/* Maximum walk depth (expression tree height after post-order recursion is
 * linearised). 64 is comfortably above anything BCF produces in practice.
 */
#define BCF_HASH_MAX_DEPTH 64

/* Sentinel: "no entry" in the open-addressed maps below. */
#define BCF_HASH_EMPTY U32_MAX

/* expr_arg_is_id mirror — bcf_checker.c:248-251. */
static inline bool bcf_arg_is_id(u8 code)
{
	return code != (BCF_BV | BCF_VAL);
}

/* is_leaf_node mirror — bcf_checker.c:1110-1113. */
static inline bool bcf_is_leaf(const struct bcf_expr *e)
{
	return e->vlen == 0 || !bcf_arg_is_id(e->code);
}

/* is_var mirror — bcf_checker.c:687-689. */
static inline bool bcf_is_var(u8 code)
{
	return (code & 0xf8) == BCF_VAR;
}

/*
 * Slot-offset → array-index lookup. Mirrors the kernel verifier's
 * id_to_expr() but for a flat expression buffer with no ref-counting.
 * An expression with vlen=n occupies 1 + n u32 slots. See spec §2.
 *
 * Implemented as a linear-probed open-addressed table.
 */
struct bcf_slot_map {
	u32 *keys;	/* slot offset; BCF_HASH_EMPTY = empty bucket */
	u32 *vals;	/* array index */
	u32 cap;	/* always a power of two */
};

static int bcf_slot_map_build(struct bcf_slot_map *m,
			      const struct bcf_expr *exprs, u32 nr_exprs)
{
	u32 cap = 16, slot = 0, i;

	while (cap < (u32)nr_exprs * 2 + 1)
		cap *= 2;

	m->cap = cap;
	m->keys = kmalloc_array(cap, sizeof(u32), GFP_KERNEL);
	m->vals = kmalloc_array(cap, sizeof(u32), GFP_KERNEL);
	if (!m->keys || !m->vals) {
		kfree(m->keys);
		kfree(m->vals);
		m->keys = m->vals = NULL;
		return -ENOMEM;
	}
	for (i = 0; i < cap; i++)
		m->keys[i] = BCF_HASH_EMPTY;

	for (i = 0; i < nr_exprs; i++) {
		u32 j = (slot * 2654435761u) & (cap - 1);

		while (m->keys[j] != BCF_HASH_EMPTY)
			j = (j + 1) & (cap - 1);
		m->keys[j] = slot;
		m->vals[j] = i;
		slot += 1u + exprs[i].vlen;
	}
	return 0;
}

static void bcf_slot_map_free(struct bcf_slot_map *m)
{
	kfree(m->keys);
	kfree(m->vals);
	m->keys = m->vals = NULL;
}

/* Returns array index or U32_MAX on miss. */
static u32 bcf_slot_map_get(const struct bcf_slot_map *m, u32 slot)
{
	u32 j = (slot * 2654435761u) & (m->cap - 1);

	while (m->keys[j] != BCF_HASH_EMPTY) {
		if (m->keys[j] == slot)
			return m->vals[j];
		j = (j + 1) & (m->cap - 1);
	}
	return U32_MAX;
}

/*
 * First-occurrence variable renamer. Same shape as bcf_slot_map but keyed
 * on var-expr-id, valued by sequential occurrence index (0, 1, 2, ...).
 */
struct bcf_var_renamer {
	u32 *keys;	/* var expr-id */
	u32 *vals;	/* first-occurrence index */
	u32 cap;	/* power of two */
	u32 used;
	u32 next;
};

static int bcf_var_renamer_init(struct bcf_var_renamer *r)
{
	u32 i;

	r->cap = 16;
	r->used = 0;
	r->next = 0;
	r->keys = kmalloc_array(r->cap, sizeof(u32), GFP_KERNEL);
	r->vals = kmalloc_array(r->cap, sizeof(u32), GFP_KERNEL);
	if (!r->keys || !r->vals) {
		kfree(r->keys);
		kfree(r->vals);
		r->keys = r->vals = NULL;
		return -ENOMEM;
	}
	for (i = 0; i < r->cap; i++)
		r->keys[i] = BCF_HASH_EMPTY;
	return 0;
}

static void bcf_var_renamer_free(struct bcf_var_renamer *r)
{
	kfree(r->keys);
	kfree(r->vals);
	r->keys = r->vals = NULL;
}

static int bcf_var_renamer_grow(struct bcf_var_renamer *r)
{
	u32 new_cap = r->cap * 2;
	u32 *nk, *nv;
	u32 i;

	nk = kmalloc_array(new_cap, sizeof(u32), GFP_KERNEL);
	nv = kmalloc_array(new_cap, sizeof(u32), GFP_KERNEL);
	if (!nk || !nv) {
		kfree(nk);
		kfree(nv);
		return -ENOMEM;
	}
	for (i = 0; i < new_cap; i++)
		nk[i] = BCF_HASH_EMPTY;
	for (i = 0; i < r->cap; i++) {
		u32 j;

		if (r->keys[i] == BCF_HASH_EMPTY)
			continue;
		j = (r->keys[i] * 2654435761u) & (new_cap - 1);
		while (nk[j] != BCF_HASH_EMPTY)
			j = (j + 1) & (new_cap - 1);
		nk[j] = r->keys[i];
		nv[j] = r->vals[i];
	}
	kfree(r->keys);
	kfree(r->vals);
	r->keys = nk;
	r->vals = nv;
	r->cap = new_cap;
	return 0;
}

/* Get-or-insert. Returns the first-occurrence index, or U32_MAX on OOM. */
static u32 bcf_var_renamer_intern(struct bcf_var_renamer *r, u32 expr_id)
{
	u32 j;

	if (r->used * 2 >= r->cap) {
		if (bcf_var_renamer_grow(r))
			return U32_MAX;
	}
	j = (expr_id * 2654435761u) & (r->cap - 1);
	while (r->keys[j] != BCF_HASH_EMPTY) {
		if (r->keys[j] == expr_id)
			return r->vals[j];
		j = (j + 1) & (r->cap - 1);
	}
	r->keys[j] = expr_id;
	r->vals[j] = r->next;
	r->used++;
	return r->next++;
}

/*
 * Growable byte buffer for the encoded record stream. Doubles on demand.
 */
struct bcf_hash_outbuf {
	u8 *data;
	size_t len;
	size_t cap;
};

static int bcf_hash_outbuf_init(struct bcf_hash_outbuf *b)
{
	b->cap = 64;
	b->len = 0;
	b->data = kmalloc(b->cap, GFP_KERNEL);
	return b->data ? 0 : -ENOMEM;
}

static void bcf_hash_outbuf_free(struct bcf_hash_outbuf *b)
{
	kfree(b->data);
	b->data = NULL;
}

static int bcf_hash_outbuf_reserve(struct bcf_hash_outbuf *b, size_t extra)
{
	size_t nc = b->cap;
	u8 *nd;

	if (b->len + extra <= b->cap)
		return 0;
	while (nc < b->len + extra)
		nc *= 2;
	nd = krealloc(b->data, nc, GFP_KERNEL);
	if (!nd)
		return -ENOMEM;
	b->data = nd;
	b->cap = nc;
	return 0;
}

static int bcf_hash_outbuf_push_u8(struct bcf_hash_outbuf *b, u8 v)
{
	int err = bcf_hash_outbuf_reserve(b, 1);

	if (err)
		return err;
	b->data[b->len++] = v;
	return 0;
}

static int bcf_hash_outbuf_push_u16_le(struct bcf_hash_outbuf *b, u16 v)
{
	int err = bcf_hash_outbuf_reserve(b, 2);

	if (err)
		return err;
	b->data[b->len++] = (u8)(v & 0xff);
	b->data[b->len++] = (u8)((v >> 8) & 0xff);
	return 0;
}

static int bcf_hash_outbuf_push_u32_le(struct bcf_hash_outbuf *b, u32 v)
{
	int err = bcf_hash_outbuf_reserve(b, 4);

	if (err)
		return err;
	b->data[b->len++] = (u8)(v & 0xff);
	b->data[b->len++] = (u8)((v >> 8) & 0xff);
	b->data[b->len++] = (u8)((v >> 16) & 0xff);
	b->data[b->len++] = (u8)((v >> 24) & 0xff);
	return 0;
}

/*
 * One frame on the post-order traversal stack. We push when descending
 * into an internal node and pop after emitting its record.
 */
struct bcf_hash_frame {
	u32 array_idx;	/* index into exprs[] */
	u32 expr_id;	/* slot offset by which this node was referenced */
	u8 next_arg;	/* index of next child to recurse into */
};

/*
 * Encode the expression rooted at `root` into `buf` per spec §3. Walks
 * post-order using an explicit stack to keep kernel stack usage bounded.
 */
static int bcf_hash_encode(u32 root,
			   const struct bcf_expr *exprs, u32 nr_exprs,
			   const struct bcf_slot_map *slots,
			   struct bcf_var_renamer *vr,
			   struct bcf_hash_outbuf *buf)
{
	struct bcf_hash_frame stack[BCF_HASH_MAX_DEPTH];
	int sp = 0;
	u32 array_idx;
	int err;

	array_idx = bcf_slot_map_get(slots, root);
	if (array_idx == U32_MAX)
		return -EINVAL;
	if (array_idx >= nr_exprs)
		return -EINVAL;

	stack[sp++] = (struct bcf_hash_frame){
		.array_idx = array_idx,
		.expr_id = root,
		.next_arg = 0,
	};

	while (sp > 0) {
		struct bcf_hash_frame *f = &stack[sp - 1];
		const struct bcf_expr *e = &exprs[f->array_idx];

		/* Leaf nodes emit immediately and pop. */
		if (bcf_is_leaf(e)) {
			if (bcf_is_var(e->code)) {
				u32 idx = bcf_var_renamer_intern(vr, f->expr_id);
				u8 i;

				if (idx == U32_MAX)
					return -ENOMEM;
				err = bcf_hash_outbuf_push_u8(buf, BCF_HASH_TAG_VAR);
				if (!err) err = bcf_hash_outbuf_push_u8(buf, e->code);
				if (!err) err = bcf_hash_outbuf_push_u8(buf, e->vlen);
				if (!err) err = bcf_hash_outbuf_push_u16_le(buf, e->params);
				if (!err) err = bcf_hash_outbuf_push_u32_le(buf, idx);
				/* Vars are nullary per BCF; spec §2. */
				for (i = 0; i < e->vlen && !err; i++)
					err = bcf_hash_outbuf_push_u32_le(buf, e->args[i]);
				if (err)
					return err;
			} else {
				u8 i;

				err = bcf_hash_outbuf_push_u8(buf, BCF_HASH_TAG_LEAF_CONST);
				if (!err) err = bcf_hash_outbuf_push_u8(buf, e->code);
				if (!err) err = bcf_hash_outbuf_push_u8(buf, e->vlen);
				if (!err) err = bcf_hash_outbuf_push_u16_le(buf, e->params);
				for (i = 0; i < e->vlen && !err; i++)
					err = bcf_hash_outbuf_push_u32_le(buf, e->args[i]);
				if (err)
					return err;
			}
			sp--;
			continue;
		}

		/* Internal node — recurse into next unvisited child. */
		if (f->next_arg < e->vlen) {
			u32 child_slot = e->args[f->next_arg++];
			u32 child_idx = bcf_slot_map_get(slots, child_slot);

			if (child_idx == U32_MAX || child_idx >= nr_exprs)
				return -EINVAL;
			if (sp >= BCF_HASH_MAX_DEPTH)
				return -E2BIG;
			stack[sp++] = (struct bcf_hash_frame){
				.array_idx = child_idx,
				.expr_id = child_slot,
				.next_arg = 0,
			};
			continue;
		}

		/* All children emitted — emit this internal node's record and pop. */
		err = bcf_hash_outbuf_push_u8(buf, BCF_HASH_TAG_INTERNAL);
		if (!err) err = bcf_hash_outbuf_push_u8(buf, e->code);
		if (!err) err = bcf_hash_outbuf_push_u8(buf, e->vlen);
		if (!err) err = bcf_hash_outbuf_push_u16_le(buf, e->params);
		if (err)
			return err;
		sp--;
	}
	return 0;
}

/*
 * Public entry. Computes the canonical hash of the expression rooted at
 * `root` in the table `exprs[0..nr_exprs)`. `root` is a slot offset (BCF's
 * on-disk id convention); see spec §2.
 *
 * Returns 0 on success and writes the hash to *out_hash. Returns -errno
 * on failure (bad slot, OOM, depth overflow).
 */
int bcf_canonical_hash(u32 root, const struct bcf_expr *exprs, u32 nr_exprs,
		       u64 *out_hash)
{
	struct bcf_slot_map slots = { 0 };
	struct bcf_var_renamer vr = { 0 };
	struct bcf_hash_outbuf buf = { 0 };
	const siphash_key_t key = { .key = { 0, 0 } };	/* spec §5 */
	int err;

	if (!exprs || !out_hash)
		return -EINVAL;
	if (nr_exprs == 0)
		return -EINVAL;

	err = bcf_slot_map_build(&slots, exprs, nr_exprs);
	if (err)
		goto out;

	err = bcf_var_renamer_init(&vr);
	if (err)
		goto out_slots;

	err = bcf_hash_outbuf_init(&buf);
	if (err)
		goto out_renamer;

	err = bcf_hash_encode(root, exprs, nr_exprs, &slots, &vr, &buf);
	if (err)
		goto out_buf;

	*out_hash = siphash(buf.data, buf.len, &key);
	err = 0;

out_buf:
	bcf_hash_outbuf_free(&buf);
out_renamer:
	bcf_var_renamer_free(&vr);
out_slots:
	bcf_slot_map_free(&slots);
out:
	return err;
}
