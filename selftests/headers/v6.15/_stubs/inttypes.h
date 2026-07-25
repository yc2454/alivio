/* Stub: <inttypes.h> for `clang -target bpf` builds.
 *
 * The selftests progs that include this don't actually use `PRI*` or
 * `imaxdiv()` in their BPF code — the include is for shared userspace
 * paths in the same source. Re-export <stdint.h> and call it good.
 */
#ifndef _ALIVIO_STUB_INTTYPES_H
#define _ALIVIO_STUB_INTTYPES_H

#include <stdint.h>

#endif
