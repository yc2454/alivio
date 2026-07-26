// SPDX-License-Identifier: GPL-2.0
/*
 * Synthetic repro for the BCF set6 `detect_conflict_eq` port.
 *
 * Pattern: along the fall-through of the *second* branch, path_conds
 * accumulate `r1 != 6` (from the first branch's not-taken edge) and then
 * `r1 == 6` (this branch's not-taken edge). That reversed-opcode pair on
 * the same `reg eq/neq const` is a syntactic contradiction. alivio's
 * interval/zone domain can't represent the `r1 != 6` disequality, so it
 * does NOT report the path inconsistent and would walk into the
 * type-collapsed `r4` load.
 *
 * Faithful to BCF set6: the conflict is detected at the SECOND BRANCH
 * (record_branch_path_conds), not at the load. The path is dropped via
 * the existing per-side drop (analog of the kernel's
 * `goto process_bpf_exit`). NO cvc5 call, NO UNREACHABLE bundle entry —
 * the target kernel's detect_conflict_eq recognizes it natively.
 *
 * Expected: PASS, the unsafe `r4` load is never reached, zero bundle
 * entries, zero solver invocations.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int access_unreach(void *ctx)
{
	asm volatile(
		"call 0x7\n\t"                  /* r0 = bpf_get_prandom_u32 (wide u32) */
		"r1 = r0\n\t"
		"if r1 == 6 goto L1_%=\n\t"     /* taken (r1==6) exits at L1 — never reaches
		                                   the 2nd branch, so no static-resolve
		                                   confound. Fall-through: r1 != 6. */
		"r4 = 0\n\t"                    /* fall-through: r4 = ScalarValue, path {r1!=6} */
		"if r1 != 6 goto END_%=\n\t"    /* taken side {r1!=6}: survives -> END.
		                                   not-taken side adds r1==6 -> the pair
		                                   {r1!=6, r1==6} is the reversed-opcode
		                                   conflict. The interval/zone domain can't
		                                   represent r1!=6, so it does NOT
		                                   static-resolve here — only
		                                   detect_conflict_eq catches it. */
		"r6 = *(u64 *)(r4 + 0)\n\t"     /* unreachable: r4=ScalarValue load, never walked */
		"END_%=:\n\t"
		"r0 = 0\n\t"
		"goto OUT_%=\n\t"
		"L1_%=:\n\t"                    /* r1==6 path exits cleanly here */
		"r0 = 0\n\t"
		"OUT_%=:\n\t"
		"r0 = 0\n\t"
		::: "r0", "r1", "r4", "r6", "memory");

	return 0;
}

char _license[] SEC("license") = "GPL";
