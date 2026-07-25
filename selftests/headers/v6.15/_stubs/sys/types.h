/* Stub: <sys/types.h> for `clang -target bpf` builds.
 *
 * Selftests sources include this for pid_t / size_t — the only
 * symbols they actually consume from sys/types in the BPF compile path.
 * Pull in the kernel UAPI types and add the POSIX aliases.
 */
#ifndef _ALIVIO_STUB_SYS_TYPES_H
#define _ALIVIO_STUB_SYS_TYPES_H

#include <linux/types.h>
#include <linux/posix_types.h>  /* __kernel_pid_t, __kernel_uid32_t, … */
#include <stddef.h>             /* size_t (clang resource header) */

typedef __kernel_pid_t  pid_t;
typedef __kernel_uid32_t uid_t;
typedef __kernel_gid32_t gid_t;
typedef __kernel_ssize_t ssize_t;
typedef __kernel_off_t  off_t;
typedef __kernel_mode_t mode_t;
typedef __kernel_time_t time_t;

#endif
