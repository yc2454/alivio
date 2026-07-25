/* Minimal in-tree stub for `linux/filter.h` — the upstream selftests
 * reach for it via `#include "../../../include/linux/filter.h"` (a
 * path that is meaningful inside the kernel tree but not here). The
 * stub is loaded via `-iquote selftests/headers/v6.15/_quotes/q1/q2/q3`
 * which lets clang resolve the relative path against this directory.
 *
 * Only the macros the selftest corpus actually uses are defined. Real
 * filter.h is much larger; if a new corpus file fails to compile
 * because something here is missing, add the minimal definition.
 */
#ifndef __ALIVIO_STUB_LINUX_FILTER_H__
#define __ALIVIO_STUB_LINUX_FILTER_H__

#include <linux/bpf.h>

#ifndef MAX_BPF_STACK
#define MAX_BPF_STACK 512
#endif

#ifndef BPF_RAW_INSN
#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)               \
    ((struct bpf_insn) {                                     \
        .code  = (CODE),                                     \
        .dst_reg = (DST),                                    \
        .src_reg = (SRC),                                    \
        .off   = (OFF),                                      \
        .imm   = (IMM) })
#endif

#ifndef BPF_ATOMIC_OP
#define BPF_ATOMIC_OP(SIZE, OP, DST, SRC, OFF)               \
    BPF_RAW_INSN(BPF_STX | (SIZE) | BPF_ATOMIC, DST, SRC, OFF, OP)
#endif

/* Insn-builder macros used by verifier_ld_ind.c, verifier_uninit.c,
 * verifier_unpriv.c, verifier_ref_tracking.c, compute_live_registers.c.
 * Copied verbatim from upstream tools/include/linux/filter.h so the
 * BPF assembly fragments those tests embed via __imm_insn(...) compile.
 */
#ifndef BPF_MOV64_REG
#define BPF_MOV64_REG(DST, SRC)                                 \
    ((struct bpf_insn) {                                        \
        .code  = BPF_ALU64 | BPF_MOV | BPF_X,                   \
        .dst_reg = DST,                                         \
        .src_reg = SRC,                                         \
        .off   = 0,                                             \
        .imm   = 0 })
#endif

#ifndef BPF_MOV64_IMM
#define BPF_MOV64_IMM(DST, IMM)                                 \
    ((struct bpf_insn) {                                        \
        .code  = BPF_ALU64 | BPF_MOV | BPF_K,                   \
        .dst_reg = DST,                                         \
        .src_reg = 0,                                           \
        .off   = 0,                                             \
        .imm   = IMM })
#endif

#ifndef BPF_LD_IND
#define BPF_LD_IND(SIZE, SRC, IMM)                              \
    ((struct bpf_insn) {                                        \
        .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND,             \
        .dst_reg = 0,                                           \
        .src_reg = SRC,                                         \
        .off   = 0,                                             \
        .imm   = IMM })
#endif

#ifndef BPF_ST_MEM
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)                         \
    ((struct bpf_insn) {                                        \
        .code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,             \
        .dst_reg = DST,                                         \
        .src_reg = 0,                                           \
        .off   = OFF,                                           \
        .imm   = IMM })
#endif

#endif /* __ALIVIO_STUB_LINUX_FILTER_H__ */
