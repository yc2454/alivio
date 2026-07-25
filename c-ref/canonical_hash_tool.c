/*
 * canonical_hash_tool — read a serialized BCF expression table on stdin,
 * print the canonical hash of the root expression as a 16-char hex digest.
 *
 * Stdin format (little-endian, no padding):
 *   u32  expr_count
 *   expr_count × {
 *       u8   code
 *       u8   vlen
 *       u16  params
 *       vlen × u32  args
 *   }
 *   u32  root_id
 *
 * Stdout: 16 hex chars + '\n'. Exit 0 on success, non-zero on I/O error.
 *
 * Used only by the cross-impl agreement test in
 * src/refinement/canonical_hash.rs. Not shipped in the kernel patch series.
 */

#include "canonical_hash.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_exact(FILE *f, void *buf, size_t n) {
    size_t got = fread(buf, 1, n, f);
    return got == n ? 0 : -1;
}

static int read_u8(FILE *f, uint8_t *out) {
    return read_exact(f, out, 1);
}

static int read_u16_le(FILE *f, uint16_t *out) {
    uint8_t b[2];
    if (read_exact(f, b, 2) != 0) return -1;
    *out = (uint16_t)b[0] | ((uint16_t)b[1] << 8);
    return 0;
}

static int read_u32_le(FILE *f, uint32_t *out) {
    uint8_t b[4];
    if (read_exact(f, b, 4) != 0) return -1;
    *out = (uint32_t)b[0]        | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    return 0;
}

int main(void) {
    uint32_t expr_count = 0;
    if (read_u32_le(stdin, &expr_count) != 0) {
        fprintf(stderr, "read expr_count: short read\n");
        return 1;
    }

    struct alivio_bcf_expr *exprs = NULL;
    uint32_t **arg_bufs = NULL;
    if (expr_count > 0) {
        exprs    = calloc(expr_count, sizeof(*exprs));
        arg_bufs = calloc(expr_count, sizeof(*arg_bufs));
        if (!exprs || !arg_bufs) {
            fprintf(stderr, "oom\n");
            return 2;
        }
    }

    for (uint32_t i = 0; i < expr_count; i++) {
        if (read_u8(stdin, &exprs[i].code) != 0 ||
            read_u8(stdin, &exprs[i].vlen) != 0 ||
            read_u16_le(stdin, &exprs[i].params) != 0) {
            fprintf(stderr, "read expr %u header: short read\n", i);
            return 1;
        }
        uint8_t vlen = exprs[i].vlen;
        if (vlen == 0) {
            exprs[i].args = NULL;
            continue;
        }
        uint32_t *args = malloc((size_t)vlen * sizeof(uint32_t));
        if (!args) { fprintf(stderr, "oom\n"); return 2; }
        for (uint8_t k = 0; k < vlen; k++) {
            if (read_u32_le(stdin, &args[k]) != 0) {
                fprintf(stderr, "read expr %u arg %u: short read\n", i, k);
                return 1;
            }
        }
        arg_bufs[i] = args;
        exprs[i].args = args;
    }

    uint32_t root = 0;
    if (read_u32_le(stdin, &root) != 0) {
        fprintf(stderr, "read root: short read\n");
        return 1;
    }

    uint64_t h = alivio_canonical_hash(root, exprs, expr_count);
    printf("%016llx\n", (unsigned long long)h);

    for (uint32_t i = 0; i < expr_count; i++) free(arg_bufs[i]);
    free(arg_bufs);
    free(exprs);
    return 0;
}
