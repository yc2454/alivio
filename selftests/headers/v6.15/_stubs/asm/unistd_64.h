/* Stub: <asm/unistd_64.h> — x86_64 syscall numbers.
 *
 * The kernel build generates this from a syscall table; the sparse
 * checkout doesn't include the generated artifact. Selftests that
 * reference syscall numbers from BPF code (`__NR_nanosleep`, etc.)
 * just need the few constants they actually compare against.
 *
 * Extend as needed; values match Linux x86_64 ABI.
 */
#ifndef _ALIVIO_STUB_ASM_UNISTD_64_H
#define _ALIVIO_STUB_ASM_UNISTD_64_H

#define __NR_nanosleep   35

#endif
