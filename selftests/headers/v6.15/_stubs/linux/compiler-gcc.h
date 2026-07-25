/* Stub: shadow tools/include/linux/compiler-gcc.h.
 *
 * The upstream tools/include/ copy of compiler-gcc.h defines `noinline`
 * as a macro expanding to `__attribute__((noinline))`. That breaks
 * selftest sources that write `__attribute__((noinline))` directly:
 * the `noinline` argument of __attribute__ is itself macro-expanded,
 * yielding the invalid `__attribute__((__attribute__((noinline))))`.
 *
 * The kernel build avoids this by not exposing tools/include/ to
 * selftests progs; we need tools/include/ for `<linux/filter.h>` and
 * a few other headers, so we shadow compiler-gcc.h with this empty
 * stub instead. None of the symbols compiler-gcc.h provides are
 * actually used in BPF compile context — `bpf_compiler.h` (vendored
 * from selftests/bpf/progs/) supplies the equivalents.
 */
#ifndef _ALIVIO_STUB_LINUX_COMPILER_GCC_H
#define _ALIVIO_STUB_LINUX_COMPILER_GCC_H
#endif
