#ifndef _ALIVIO_STUB_LINUX_VERSION_H
#define _ALIVIO_STUB_LINUX_VERSION_H
/* Stub — selftests reference LINUX_VERSION_CODE for the `version`
 * section emitted by old kprobe progs. Any plausible value compiles;
 * the verifier doesn't validate kernel-version pinning. */
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#define LINUX_VERSION_CODE KERNEL_VERSION(6, 15, 0)
#endif
