/*
 * SipHash-2-4 — reference implementation, header-only.
 *
 * Public-domain port of the canonical implementation by
 * Jean-Philippe Aumasson and Daniel J. Bernstein:
 *   https://github.com/veorq/SipHash
 *
 * Kept self-contained and dependency-free so the kernel patch series can
 * vendor it without dragging in external headers. The kernel itself has
 * `include/linux/siphash.h`; this file exists for the userspace reference
 * implementation and the cross-impl test harness only.
 */

#ifndef ALIVIO_SIPHASH24_H
#define ALIVIO_SIPHASH24_H

#include <stdint.h>
#include <stddef.h>

static inline uint64_t siphash24_rotl(uint64_t x, int b) {
    return (x << b) | (x >> (64 - b));
}

#define SIPHASH24_ROUND(v0, v1, v2, v3) do { \
    v0 += v1; v1 = siphash24_rotl(v1, 13); v1 ^= v0; v0 = siphash24_rotl(v0, 32); \
    v2 += v3; v3 = siphash24_rotl(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = siphash24_rotl(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = siphash24_rotl(v1, 17); v1 ^= v2; v2 = siphash24_rotl(v2, 32); \
} while (0)

/* Compute SipHash-2-4 over `in` (length `inlen`) with 128-bit key (k0, k1). */
static inline uint64_t siphash24(const uint8_t *in, size_t inlen,
                                 uint64_t k0, uint64_t k1) {
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    const uint8_t *end = in + inlen - (inlen % 8);
    const int left = (int)(inlen & 7);
    uint64_t b = ((uint64_t)inlen) << 56;

    while (in != end) {
        uint64_t m = (uint64_t)in[0]       | (uint64_t)in[1] << 8 |
                     (uint64_t)in[2] << 16 | (uint64_t)in[3] << 24 |
                     (uint64_t)in[4] << 32 | (uint64_t)in[5] << 40 |
                     (uint64_t)in[6] << 48 | (uint64_t)in[7] << 56;
        v3 ^= m;
        SIPHASH24_ROUND(v0, v1, v2, v3);
        SIPHASH24_ROUND(v0, v1, v2, v3);
        v0 ^= m;
        in += 8;
    }

    switch (left) {
        case 7: b |= ((uint64_t)in[6]) << 48; /* fallthrough */
        case 6: b |= ((uint64_t)in[5]) << 40; /* fallthrough */
        case 5: b |= ((uint64_t)in[4]) << 32; /* fallthrough */
        case 4: b |= ((uint64_t)in[3]) << 24; /* fallthrough */
        case 3: b |= ((uint64_t)in[2]) << 16; /* fallthrough */
        case 2: b |= ((uint64_t)in[1]) << 8;  /* fallthrough */
        case 1: b |= ((uint64_t)in[0]);       /* fallthrough */
        case 0: break;
    }

    v3 ^= b;
    SIPHASH24_ROUND(v0, v1, v2, v3);
    SIPHASH24_ROUND(v0, v1, v2, v3);
    v0 ^= b;

    v2 ^= 0xff;
    SIPHASH24_ROUND(v0, v1, v2, v3);
    SIPHASH24_ROUND(v0, v1, v2, v3);
    SIPHASH24_ROUND(v0, v1, v2, v3);
    SIPHASH24_ROUND(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

#endif /* ALIVIO_SIPHASH24_H */
