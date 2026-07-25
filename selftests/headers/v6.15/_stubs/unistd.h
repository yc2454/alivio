/* Stub: <unistd.h> — minimal POSIX shim for BPF compile path.
 *
 * Selftests sources include this for shared userspace paths; the BPF
 * code itself doesn't call read/write/close. Provide just the typedefs
 * and a few constants that the include chain references.
 */
#ifndef _ALIVIO_STUB_UNISTD_H
#define _ALIVIO_STUB_UNISTD_H
#include <sys/types.h>
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#endif
