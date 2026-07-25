/* Stub for upstream bpf_arena_common.h.
 *
 * Real header lives at tools/testing/selftests/bpf/bpf_arena_common.h
 * and provides a tagged-pointer abstraction for the BPF arena map.
 * For our verifier, the only things the corpus actually needs to
 * compile are the `__arena` qualifier (becomes a no-op address-space
 * tag), the kfunc declarations, and `NUMA_NO_NODE`. Verification of
 * these programs goes through the unified arena CallProto that W5.5
 * landed.
 */
#ifndef _ALIVIO_STUB_BPF_ARENA_COMMON_H
#define _ALIVIO_STUB_BPF_ARENA_COMMON_H

#ifndef __arena
#define __arena __attribute__((address_space(1)))
#endif

#ifndef NUMA_NO_NODE
#define NUMA_NO_NODE (-1)
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr__hint,
                                    unsigned int page_cnt, int node_id,
                                    unsigned long flags) __ksym;
void bpf_arena_free_pages(void *map, void __arena *ptr__ign,
                          unsigned int page_cnt) __ksym;

#endif
