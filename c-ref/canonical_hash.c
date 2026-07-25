/*
 * BCF canonical hash — C reference implementation.
 * See canonical_hash.h.
 */

#include "canonical_hash.h"
#include "siphash24.h"

#include <stdlib.h>
#include <string.h>

/* Constants mirroring src/refinement/bcf.rs. */
#define BCF_TYPE_MASK 0x07
#define BCF_OP_MASK   0xf8
#define BCF_BV        0x00
#define BCF_VAL       0x08
#define BCF_VAR       0x18

/* Record tags. See spec §3.1. */
#define TAG_VAR        0x01
#define TAG_LEAF_CONST 0x02
#define TAG_INTERNAL   0x03

/* expr_arg_is_id mirror: bcf_checker.c:248-251. */
static inline int expr_arg_is_id(uint8_t code) {
    return code != (BCF_BV | BCF_VAL);
}

/* is_leaf_node mirror: bcf_checker.c:1110-1113. */
static inline int is_leaf(const struct alivio_bcf_expr *e) {
    return e->vlen == 0 || !expr_arg_is_id(e->code);
}

/* is_var mirror: bcf_checker.c:687-689. */
static inline int is_var(uint8_t code) {
    return (code & BCF_OP_MASK) == BCF_VAR;
}

/*
 * First-occurrence renamer. Open-addressed flat array — variable expression
 * counts in real BCF proofs are small (≤ low hundreds), so linear probing on
 * a power-of-two table is cheaper and simpler than a hash table.
 *
 * Capacity grows by doubling. Initial 16 slots covers typical sizes without
 * reallocation.
 */
struct renamer {
    uint32_t *keys;   /* expr-id; UINT32_MAX = empty slot */
    uint32_t *vals;   /* first-occurrence index */
    size_t    cap;    /* always a power of two */
    size_t    used;
    uint32_t  next;
};

#define RENAMER_EMPTY UINT32_MAX

static int renamer_init(struct renamer *r) {
    r->cap = 16;
    r->used = 0;
    r->next = 0;
    r->keys = malloc(r->cap * sizeof(uint32_t));
    r->vals = malloc(r->cap * sizeof(uint32_t));
    if (!r->keys || !r->vals) return -1;
    for (size_t i = 0; i < r->cap; i++) r->keys[i] = RENAMER_EMPTY;
    return 0;
}

static void renamer_free(struct renamer *r) {
    free(r->keys); free(r->vals);
    r->keys = NULL; r->vals = NULL;
}

/* Knuth multiplicative hash, low bits. */
static inline size_t renamer_slot(uint32_t key, size_t cap) {
    return (size_t)(key * 2654435761u) & (cap - 1);
}

static int renamer_grow(struct renamer *r) {
    size_t new_cap = r->cap * 2;
    uint32_t *nk = malloc(new_cap * sizeof(uint32_t));
    uint32_t *nv = malloc(new_cap * sizeof(uint32_t));
    if (!nk || !nv) { free(nk); free(nv); return -1; }
    for (size_t i = 0; i < new_cap; i++) nk[i] = RENAMER_EMPTY;
    for (size_t i = 0; i < r->cap; i++) {
        if (r->keys[i] == RENAMER_EMPTY) continue;
        size_t j = renamer_slot(r->keys[i], new_cap);
        while (nk[j] != RENAMER_EMPTY) j = (j + 1) & (new_cap - 1);
        nk[j] = r->keys[i];
        nv[j] = r->vals[i];
    }
    free(r->keys); free(r->vals);
    r->keys = nk; r->vals = nv; r->cap = new_cap;
    return 0;
}

/* Returns the first-occurrence index for `expr_id`, allocating one on first
 * visit. Returns UINT32_MAX on allocation failure. */
static uint32_t renamer_intern(struct renamer *r, uint32_t expr_id) {
    if (r->used * 2 >= r->cap) {
        if (renamer_grow(r) != 0) return RENAMER_EMPTY;
    }
    size_t j = renamer_slot(expr_id, r->cap);
    while (r->keys[j] != RENAMER_EMPTY) {
        if (r->keys[j] == expr_id) return r->vals[j];
        j = (j + 1) & (r->cap - 1);
    }
    r->keys[j] = expr_id;
    r->vals[j] = r->next;
    r->used++;
    return r->next++;
}

/* Output buffer for the encoded byte stream. */
struct outbuf {
    uint8_t *data;
    size_t   len;
    size_t   cap;
    int      oom;
};

static int outbuf_init(struct outbuf *b) {
    b->cap = 64;
    b->len = 0;
    b->oom = 0;
    b->data = malloc(b->cap);
    return b->data ? 0 : -1;
}

static void outbuf_free(struct outbuf *b) { free(b->data); b->data = NULL; }

static void outbuf_reserve(struct outbuf *b, size_t extra) {
    if (b->oom) return;
    if (b->len + extra <= b->cap) return;
    size_t nc = b->cap;
    while (nc < b->len + extra) nc *= 2;
    uint8_t *nd = realloc(b->data, nc);
    if (!nd) { b->oom = 1; return; }
    b->data = nd; b->cap = nc;
}

static void outbuf_push_u8(struct outbuf *b, uint8_t v) {
    outbuf_reserve(b, 1);
    if (b->oom) return;
    b->data[b->len++] = v;
}

static void outbuf_push_u16_le(struct outbuf *b, uint16_t v) {
    outbuf_reserve(b, 2);
    if (b->oom) return;
    b->data[b->len++] = (uint8_t)(v & 0xff);
    b->data[b->len++] = (uint8_t)((v >> 8) & 0xff);
}

static void outbuf_push_u32_le(struct outbuf *b, uint32_t v) {
    outbuf_reserve(b, 4);
    if (b->oom) return;
    b->data[b->len++] = (uint8_t)(v & 0xff);
    b->data[b->len++] = (uint8_t)((v >> 8)  & 0xff);
    b->data[b->len++] = (uint8_t)((v >> 16) & 0xff);
    b->data[b->len++] = (uint8_t)((v >> 24) & 0xff);
}

/* Slot-offset → array-index lookup. Args in BCF expressions are u32 slot
 * offsets (each expression occupies 1 + vlen slots); userspace must resolve
 * to array positions before indexing into `exprs`. See spec §2.
 *
 * Linear-probe hash table keyed by slot offset. Capacity sized so load
 * factor stays ≤ 0.5.
 */
struct slot_table {
    uint32_t *keys;  /* slot offset; UINT32_MAX = empty */
    uint32_t *vals;  /* array index */
    size_t    cap;
};

#define SLOT_EMPTY UINT32_MAX

static int slot_table_build(struct slot_table *t,
                            const struct alivio_bcf_expr *exprs,
                            size_t exprs_len) {
    size_t cap = 16;
    while (cap < exprs_len * 2 + 1) cap *= 2;
    t->cap = cap;
    t->keys = malloc(cap * sizeof(uint32_t));
    t->vals = malloc(cap * sizeof(uint32_t));
    if (!t->keys || !t->vals) return -1;
    for (size_t i = 0; i < cap; i++) t->keys[i] = SLOT_EMPTY;

    uint32_t slot = 0;
    for (size_t i = 0; i < exprs_len; i++) {
        size_t j = (size_t)(slot * 2654435761u) & (cap - 1);
        while (t->keys[j] != SLOT_EMPTY) j = (j + 1) & (cap - 1);
        t->keys[j] = slot;
        t->vals[j] = (uint32_t)i;
        slot += 1u + (uint32_t)exprs[i].vlen;
    }
    return 0;
}

static void slot_table_free(struct slot_table *t) {
    free(t->keys); free(t->vals);
    t->keys = NULL; t->vals = NULL;
}

/* Returns the array index for a slot offset, or SIZE_MAX if not found. */
static size_t slot_table_get(const struct slot_table *t, uint32_t slot) {
    size_t j = (size_t)(slot * 2654435761u) & (t->cap - 1);
    while (t->keys[j] != SLOT_EMPTY) {
        if (t->keys[j] == slot) return (size_t)t->vals[j];
        j = (j + 1) & (t->cap - 1);
    }
    return (size_t)-1;
}

/* Recursive post-order encoder. Mirrors `encode()` in canonical_hash.rs. */
static void encode(uint32_t id, const struct alivio_bcf_expr *exprs,
                   const struct slot_table *st,
                   struct renamer *r, struct outbuf *b) {
    size_t array_idx = slot_table_get(st, id);
    if (array_idx == (size_t)-1) { b->oom = 1; return; }
    const struct alivio_bcf_expr *e = &exprs[array_idx];

    if (is_leaf(e)) {
        if (is_var(e->code)) {
            uint32_t idx = renamer_intern(r, id);
            if (idx == RENAMER_EMPTY) { b->oom = 1; return; }
            outbuf_push_u8(b, TAG_VAR);
            outbuf_push_u8(b, e->code);
            outbuf_push_u8(b, e->vlen);
            outbuf_push_u16_le(b, e->params);
            outbuf_push_u32_le(b, idx);
        } else {
            outbuf_push_u8(b, TAG_LEAF_CONST);
            outbuf_push_u8(b, e->code);
            outbuf_push_u8(b, e->vlen);
            outbuf_push_u16_le(b, e->params);
            for (uint8_t i = 0; i < e->vlen; i++) {
                outbuf_push_u32_le(b, e->args[i]);
            }
        }
    } else {
        for (uint8_t i = 0; i < e->vlen; i++) {
            encode(e->args[i], exprs, st, r, b);
            if (b->oom) return;
        }
        outbuf_push_u8(b, TAG_INTERNAL);
        outbuf_push_u8(b, e->code);
        outbuf_push_u8(b, e->vlen);
        outbuf_push_u16_le(b, e->params);
    }
}

uint64_t alivio_canonical_hash(uint32_t root,
                              const struct alivio_bcf_expr *exprs,
                              size_t exprs_len) {
    struct renamer    r;
    struct outbuf     b;
    struct slot_table st;
    uint64_t h = 0;

    if (renamer_init(&r) != 0) return 0;
    if (outbuf_init(&b)  != 0) { renamer_free(&r); return 0; }
    if (slot_table_build(&st, exprs, exprs_len) != 0) {
        outbuf_free(&b); renamer_free(&r); return 0;
    }

    encode(root, exprs, &st, &r, &b);

    if (!b.oom) {
        h = siphash24(b.data, b.len, 0, 0);
    }

    slot_table_free(&st);

    outbuf_free(&b);
    renamer_free(&r);
    return h;
}
